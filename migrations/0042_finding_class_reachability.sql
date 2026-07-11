-- +goose Up
-- Coarse JVM class-reachability verdict (RX / RJ1): whether the app's own compiled code (transitively)
-- references the finding's component. "reachable" | "unreferenced" | "" (unknown/not analyzed). Advisory
-- only – it deprioritizes an unreferenced component's finding (already reflected in `priority`) and lets a
-- report/export SEPARATE used from unreferenced deps; it never suppresses a finding. Default '' keeps
-- existing rows valid (unknown).
ALTER TABLE findings ADD COLUMN class_reachability TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE findings DROP COLUMN class_reachability;
