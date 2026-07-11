package codeanalysis

import "testing"

// TestRuleCorpus is the per-rule true/false-positive regression corpus: every true-positive line MUST be
// flagged by its rule and every false-positive line MUST NOT be. Guards precision as the set grows.
func TestRuleCorpus(t *testing.T) {
	rs := builtinRules()
	rules := map[string]*rule{}
	for i := range rs {
		rules[rs[i].id] = &rs[i]
	}
	corpus := []struct {
		id string
		tp []string
		fp []string
	}{
		{
			id: "quality-todo-comment",
			tp: []string{"// TODO: refactor", "# FIXME later", "  * XXX broken", "-- HACK: temporary"},
			fp: []string{"// a normal explanatory comment", "var todo = 1", "return fixme"},
		},
		{
			id: "quality-commented-out-code",
			tp: []string{"// x = foo(a);", "# result = compute(b);", "// if (ready) {"},
			fp: []string{"// this explains the function", "// see https://example.com/docs", "# a plain note"},
		},
		{
			id: "reliability-empty-catch",
			tp: []string{"} catch (e) {}", "  catch(Exception ex) {}", "except ValueError: pass"},
			fp: []string{"} catch (e) { log(e); }", "except ValueError: handle()"},
		},
		{
			id: "reliability-self-assignment",
			tp: []string{"y = y;", "a.b = a.b", "count = count // keep"},
			fp: []string{"y = y + 1;", "a = b", "x == x", "total = total - 1"},
		},
		{
			id: "reliability-self-comparison",
			tp: []string{"if (x == x) {", "return a.b != a.b;", "while (i == i)"},
			fp: []string{"if (x == y) {", "if (a != b) {", "z = z"},
		},
	}
	for _, c := range corpus {
		r, ok := rules[c.id]
		if !ok {
			t.Fatalf("rule %q not found", c.id)
		}
		for _, tp := range c.tp {
			if !r.hit(tp) {
				t.Errorf("[%s] MISS true-positive: %q", c.id, tp)
			}
		}
		for _, fp := range c.fp {
			if r.hit(fp) {
				t.Errorf("[%s] FALSE POSITIVE: %q", c.id, fp)
			}
		}
	}
}
