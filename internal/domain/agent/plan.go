package agent

import (
	"fmt"
	"time"

	"github.com/KKloudTarus/synapse-ce/internal/domain/shared"
)

// Plan is an LLM-PROPOSED, Go-VALIDATED execution graph.
// The LLM proposes a set of recon steps and their dependencies; Go mints the node ids,
// classifies each node's risk, and validates the graph (acyclic, bounded, well-formed) before
// anything runs. A node carries NO authority: when the scheduler runs it, the node's action is
// RE-ADMITTED through safety.Gate.Admit exactly like a reactive proposal – the plan only
// expresses ORDER + intent, never permission. Plans are append-only (replan adds nodes; it
// never edits a settled one) and versioned with an optimistic-concurrency Revision so a
// node-status change is an atomic compare-and-swap (the durable idempotency authority: a
// redelivered driver that loses the CAS cannot double-run a node).
//
// This file is pure domain: it imports only shared + stdlib and owns every DAG invariant, so
// the planner (catalog) and the scheduler (orchestrator) share one validated type.

// NodeStatus is a plan node's lifecycle. A node starts NodePending; the scheduler claims it
// (NodeRunning), then settles it to one terminal state. Awaiting is a non-terminal suspension
// on a manual HITL decision (survives restart, like the session's awaiting_approval).
type NodeStatus string

const (
	NodePending  NodeStatus = "pending"  // not yet run; eligible once its deps are NodeDone
	NodeRunning  NodeStatus = "running"  // claimed + executing (crash-recovery re-drives it idempotently)
	NodeAwaiting NodeStatus = "awaiting" // suspended on a manual HITL approval
	NodeDone     NodeStatus = "done"     // executed + sealed (terminal, success)
	NodeDenied   NodeStatus = "denied"   // gate denied (scope/window/RoE/human-deny); terminal, blocks dependents
	NodeSkipped  NodeStatus = "skipped"  // a dependency was blocking, so this can never run; terminal
	NodeFailed   NodeStatus = "failed"   // execution error / retries exhausted; terminal, blocks dependents
)

// Terminal reports whether the node has settled (no further work).
func (s NodeStatus) Terminal() bool {
	switch s {
	case NodeDone, NodeDenied, NodeSkipped, NodeFailed:
		return true
	default:
		return false
	}
}

// blocksDependents reports whether settling in this state means a dependent can never run (so
// the dependent must be NodeSkipped). NodeDone unblocks; the failure-ish terminals cascade.
func (s NodeStatus) blocksDependents() bool {
	switch s {
	case NodeDenied, NodeSkipped, NodeFailed:
		return true
	default:
		return false
	}
}

// PlanNode is one step in the plan. ID + ActionID + Risk are Go-minted/Go-classified (never
// LLM-supplied): the LLM proposes only Tool + Target + DependsOn + a rationale. ActionID is
// minted ONCE at plan creation and reused on every (re)admission of this node, so the
// evidence-chain idempotency (alreadyExecuted) is stable across redeliveries/crashes. Failure
// must be redacted by the caller before persisting (it may echo tool output).
type PlanNode struct {
	ID         string     `json:"id"`
	Tool       string     `json:"tool"`
	Target     string     `json:"target"`
	DependsOn  []string   `json:"depends_on,omitempty"`
	Status     NodeStatus `json:"status"`
	Retries    int        `json:"retries"`
	MaxRetries int        `json:"max_retries"`
	ActionID   shared.ID  `json:"action_id"`
	Risk       RiskClass  `json:"risk"`
	Rationale  string     `json:"rationale,omitempty"`
	Failure    string     `json:"failure,omitempty"`
}

// PlanStatus is the plan's overall disposition (distinct from per-node status).
type PlanStatus string

const (
	PlanDraft    PlanStatus = "draft"    // reserved: proposed but not yet driven
	PlanActive   PlanStatus = "active"   // being executed
	PlanComplete PlanStatus = "complete" // all nodes settled, none failed/denied/skipped
	PlanFailed   PlanStatus = "failed"   // settled with at least one failed/denied/skipped node
)

// Plan is the validated DAG for a session. Revision is the optimistic-concurrency token: a
// SavePlan succeeds only if the stored revision still matches (lost-update guard), which makes
// a node claim atomic across concurrent/redelivered drivers.
type Plan struct {
	ID           shared.ID  `json:"id"`
	SessionID    shared.ID  `json:"session_id"`
	EngagementID shared.ID  `json:"engagement_id"`
	Goal         string     `json:"goal"`
	Status       PlanStatus `json:"status"`
	Revision     int        `json:"revision"`
	Nodes        []PlanNode `json:"nodes"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// Plan size bounds (defense against a hostile/runaway model proposing an enormous graph that
// would blow the step/token budget or the DB row). A plan exceeding these is rejected at
// NewPlan – never silently truncated.
const (
	MaxPlanNodes          = 32 // total nodes in a plan
	MaxNodeFanout         = 16 // dependencies a single node may declare
	defaultNodeMaxRetries = 1  // attempts per node (PR3 runs once; retry loop is reserved for PR5)
)

// NewPlan validates the proposed graph and returns a ready-to-drive (active) plan with every
// node Pending. It rejects: missing ids/goal, an empty or oversized node set, a node with too
// many dependencies, a duplicate node id, a dependency on an unknown node, a self-dependency,
// and any cycle (Kahn topological sort). The caller (catalog) has already minted node ids,
// translated the LLM's dependency labels to ids, and classified risk; NewPlan owns the
// structural invariants so the scheduler can trust the graph.
func NewPlan(id, sessionID, engagementID shared.ID, goal string, nodes []PlanNode, now time.Time) (Plan, error) {
	if id == "" || sessionID == "" || engagementID == "" {
		return Plan{}, fmt.Errorf("%w: plan needs id + session + engagement", shared.ErrValidation)
	}
	if goal == "" {
		return Plan{}, fmt.Errorf("%w: plan needs a goal", shared.ErrValidation)
	}
	if len(nodes) == 0 {
		return Plan{}, fmt.Errorf("%w: plan needs at least one node", shared.ErrValidation)
	}
	if len(nodes) > MaxPlanNodes {
		return Plan{}, fmt.Errorf("%w: plan has %d nodes (max %d)", shared.ErrValidation, len(nodes), MaxPlanNodes)
	}
	ids := make(map[string]bool, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		if n.ID == "" || n.Tool == "" || n.Target == "" {
			return Plan{}, fmt.Errorf("%w: every plan node needs id + tool + target", shared.ErrValidation)
		}
		if ids[n.ID] {
			return Plan{}, fmt.Errorf("%w: duplicate plan node id %q", shared.ErrValidation, n.ID)
		}
		ids[n.ID] = true
	}
	for i := range nodes {
		n := &nodes[i]
		if len(n.DependsOn) > MaxNodeFanout {
			return Plan{}, fmt.Errorf("%w: node %q has %d deps (max %d)", shared.ErrValidation, n.ID, len(n.DependsOn), MaxNodeFanout)
		}
		seen := make(map[string]bool, len(n.DependsOn))
		for _, dep := range n.DependsOn {
			if dep == n.ID {
				return Plan{}, fmt.Errorf("%w: node %q depends on itself", shared.ErrValidation, n.ID)
			}
			if !ids[dep] {
				return Plan{}, fmt.Errorf("%w: node %q depends on unknown node %q", shared.ErrValidation, n.ID, dep)
			}
			if seen[dep] {
				return Plan{}, fmt.Errorf("%w: node %q lists dependency %q twice", shared.ErrValidation, n.ID, dep)
			}
			seen[dep] = true
		}
		if n.Status == "" {
			n.Status = NodePending
		}
		if n.MaxRetries <= 0 {
			n.MaxRetries = defaultNodeMaxRetries
		}
	}
	if err := assertAcyclic(nodes); err != nil {
		return Plan{}, err
	}
	return Plan{
		ID: id, SessionID: sessionID, EngagementID: engagementID, Goal: goal,
		Status: PlanActive, Revision: 1, Nodes: nodes, CreatedAt: now, UpdatedAt: now,
	}, nil
}

// assertAcyclic runs Kahn's algorithm; if not every node is removable the graph has a cycle.
func assertAcyclic(nodes []PlanNode) error {
	indeg := make(map[string]int, len(nodes))
	dependents := make(map[string][]string, len(nodes))
	for i := range nodes {
		indeg[nodes[i].ID] = len(nodes[i].DependsOn)
		for _, dep := range nodes[i].DependsOn {
			dependents[dep] = append(dependents[dep], nodes[i].ID)
		}
	}
	queue := make([]string, 0, len(nodes))
	for id, d := range indeg {
		if d == 0 {
			queue = append(queue, id)
		}
	}
	removed := 0
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		removed++
		for _, dep := range dependents[id] {
			indeg[dep]--
			if indeg[dep] == 0 {
				queue = append(queue, dep)
			}
		}
	}
	if removed != len(nodes) {
		return fmt.Errorf("%w: plan graph has a cycle", shared.ErrValidation)
	}
	return nil
}

// node returns a pointer to the node with id (and whether it exists).
func (p *Plan) node(id string) (*PlanNode, bool) {
	for i := range p.Nodes {
		if p.Nodes[i].ID == id {
			return &p.Nodes[i], true
		}
	}
	return nil, false
}

// Node returns a copy of the node with id (read access for callers outside the package).
func (p Plan) Node(id string) (PlanNode, bool) {
	for _, n := range p.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return PlanNode{}, false
}

// Ready returns the ids of nodes eligible to run now: NodePending, every dependency NodeDone,
// and attempts not yet exhausted (Retries < MaxRetries) so a deterministically-failing node
// cannot burn the step budget. Order is stable (plan order) for deterministic scheduling.
func (p Plan) Ready() []string {
	var out []string
	for _, n := range p.Nodes {
		if n.Status != NodePending || n.Retries >= n.MaxRetries {
			continue
		}
		ok := true
		for _, dep := range n.DependsOn {
			d, found := p.Node(dep)
			if !found || d.Status != NodeDone {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, n.ID)
		}
	}
	return out
}

// ReadyActive returns up to max ready node ids that are RiskActive – the candidates a scheduler
// may run CONCURRENTLY. RiskIntrusive nodes are deliberately excluded: they always need
// manual approval and are run strictly one-at-a-time (never two intrusive in flight), so the
// serial path handles them. Order is stable (plan order). max<=0 returns nothing.
func (p Plan) ReadyActive(max int) []string {
	if max <= 0 {
		return nil
	}
	var out []string
	for _, id := range p.Ready() {
		n, ok := p.Node(id)
		if !ok || n.Risk != RiskActive {
			continue
		}
		out = append(out, id)
		if len(out) >= max {
			break
		}
	}
	return out
}

// FirstUnsettledClaimed returns the id of a node already claimed (NodeRunning) or suspended
// (NodeAwaiting) – work the scheduler must resolve before picking new Ready nodes. NodeRunning
// is crash-recovery (re-drive idempotently); NodeAwaiting is a HITL resume. Empty if none.
func (p Plan) FirstUnsettledClaimed() string {
	for _, n := range p.Nodes {
		if n.Status == NodeRunning || n.Status == NodeAwaiting {
			return n.ID
		}
	}
	return ""
}

// SetNodeStatus updates a node's status (and optionally a redacted failure reason). Returns an
// error if the id is unknown – the scheduler owns transitions, so an unknown id is a bug.
func (p *Plan) SetNodeStatus(id string, status NodeStatus, failure string) error {
	n, ok := p.node(id)
	if !ok {
		return fmt.Errorf("%w: unknown plan node %q", shared.ErrValidation, id)
	}
	n.Status = status
	if failure != "" {
		n.Failure = failure
	}
	return nil
}

// AppendNodes adds new nodes to the plan (append-only replan). It NEVER mutates an existing
// node (settled or not), rejects a new node whose dependency is already a blocking terminal (a
// dead dependency that could never become NodeDone), and revalidates the COMBINED graph stays
// within caps, has unique ids, references only known nodes, and is acyclic. The new nodes start
// NodePending. SavePlan bumps the revision; this only edits the in-memory node set.
func (p *Plan) AppendNodes(newNodes []PlanNode) error {
	if len(newNodes) == 0 {
		return fmt.Errorf("%w: AppendNodes needs at least one node", shared.ErrValidation)
	}
	if len(p.Nodes)+len(newNodes) > MaxPlanNodes {
		return fmt.Errorf("%w: appending %d nodes exceeds the %d-node cap", shared.ErrValidation, len(newNodes), MaxPlanNodes)
	}
	existing := make(map[string]NodeStatus, len(p.Nodes))
	for _, n := range p.Nodes {
		existing[n.ID] = n.Status
	}
	for i := range newNodes {
		n := &newNodes[i]
		if n.ID == "" || n.Tool == "" || n.Target == "" {
			return fmt.Errorf("%w: every appended node needs id + tool + target", shared.ErrValidation)
		}
		if _, dup := existing[n.ID]; dup {
			return fmt.Errorf("%w: appended node id %q already exists", shared.ErrValidation, n.ID)
		}
		for _, dep := range n.DependsOn {
			if st, ok := existing[dep]; ok && st.blocksDependents() {
				return fmt.Errorf("%w: appended node %q depends on dead node %q (%s)", shared.ErrValidation, n.ID, dep, st)
			}
		}
		if n.Status == "" {
			n.Status = NodePending
		}
		if n.MaxRetries <= 0 {
			n.MaxRetries = defaultNodeMaxRetries
		}
	}
	combined := append(append(make([]PlanNode, 0, len(p.Nodes)+len(newNodes)), p.Nodes...), newNodes...)
	// Revalidate structure (unique ids, known + non-self deps, fanout, acyclic) over the union.
	if _, err := validateGraph(combined); err != nil {
		return err
	}
	p.Nodes = combined
	if p.Status == PlanComplete || p.Status == PlanFailed {
		p.Status = PlanActive // re-opened by a replan
	}
	return nil
}

// validateGraph checks the structural invariants over a node set (shared by AppendNodes; NewPlan
// inlines the same checks plus the status/retry defaulting). Returns the validated nodes.
func validateGraph(nodes []PlanNode) ([]PlanNode, error) {
	if len(nodes) == 0 || len(nodes) > MaxPlanNodes {
		return nil, fmt.Errorf("%w: plan must have 1..%d nodes", shared.ErrValidation, MaxPlanNodes)
	}
	ids := make(map[string]bool, len(nodes))
	for i := range nodes {
		if nodes[i].ID == "" {
			return nil, fmt.Errorf("%w: a plan node is missing its id", shared.ErrValidation)
		}
		if ids[nodes[i].ID] {
			return nil, fmt.Errorf("%w: duplicate plan node id %q", shared.ErrValidation, nodes[i].ID)
		}
		ids[nodes[i].ID] = true
	}
	for i := range nodes {
		n := &nodes[i]
		if len(n.DependsOn) > MaxNodeFanout {
			return nil, fmt.Errorf("%w: node %q has %d deps (max %d)", shared.ErrValidation, n.ID, len(n.DependsOn), MaxNodeFanout)
		}
		for _, dep := range n.DependsOn {
			if dep == n.ID {
				return nil, fmt.Errorf("%w: node %q depends on itself", shared.ErrValidation, n.ID)
			}
			if !ids[dep] {
				return nil, fmt.Errorf("%w: node %q depends on unknown node %q", shared.ErrValidation, n.ID, dep)
			}
		}
	}
	if err := assertAcyclic(nodes); err != nil {
		return nil, err
	}
	return nodes, nil
}

// PropagateFailures cascades blocking terminals: any NodePending node that depends (directly)
// on a blocking node (denied/skipped/failed) becomes NodeSkipped. Run to a fixed point so the
// skip propagates transitively. Returns the ids newly skipped.
func (p *Plan) PropagateFailures() []string {
	var changed []string
	for {
		any := false
		for i := range p.Nodes {
			n := &p.Nodes[i]
			if n.Status != NodePending {
				continue
			}
			for _, dep := range n.DependsOn {
				if d, ok := p.node(dep); ok && d.Status.blocksDependents() {
					n.Status = NodeSkipped
					changed = append(changed, n.ID)
					any = true
					break
				}
			}
		}
		if !any {
			return changed
		}
	}
}

// AllSettled reports whether every node has reached a terminal status.
func (p Plan) AllSettled() bool {
	for _, n := range p.Nodes {
		if !n.Status.Terminal() {
			return false
		}
	}
	return true
}

// AwaitingApproval reports whether any node is suspended on a manual HITL decision.
func (p Plan) AwaitingApproval() bool {
	for _, n := range p.Nodes {
		if n.Status == NodeAwaiting {
			return true
		}
	}
	return false
}

// Settled is true once the plan is in a terminal PlanStatus.
func (s PlanStatus) Settled() bool { return s == PlanComplete || s == PlanFailed }

// RecomputeStatus derives the plan status from its nodes: still PlanActive until every node is
// terminal; then PlanComplete iff all nodes are NodeDone, else PlanFailed (any denied/skipped/
// failed node means the plan did not fully execute). It never moves a plan OUT of a terminal
// status. Returns the (possibly unchanged) status.
func (p *Plan) RecomputeStatus() PlanStatus {
	if p.Status.Settled() {
		return p.Status
	}
	if !p.AllSettled() {
		p.Status = PlanActive
		return p.Status
	}
	p.Status = PlanComplete
	for _, n := range p.Nodes {
		if n.Status != NodeDone {
			p.Status = PlanFailed
			break
		}
	}
	return p.Status
}
