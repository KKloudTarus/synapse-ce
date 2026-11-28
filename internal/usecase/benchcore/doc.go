// Package benchcore is the engine-neutral core of the benchmark system (#1640): the closure-scope
// manifest that freezes what a benchmark run claims before it runs, the run-start receipt that binds a
// run to one manifest revision, the observation and truth documents an adapter and an oracle exchange,
// the scorer that turns them into cells without ever seeing an engine's identity, and the scorecard that
// binds a score to the manifest, receipt, truth and observation digests it came from.
//
// The package imports no engine. An adapter produces an Observation; it cannot supply labels, counts or a
// verdict, because the document has no field for them and StrictDecode refuses unknown fields. Score takes
// truth and observations and nothing that names an engine, so renaming or reordering engines cannot change
// a standalone grade. Identity is attached afterwards by BindScorecard.
package benchcore
