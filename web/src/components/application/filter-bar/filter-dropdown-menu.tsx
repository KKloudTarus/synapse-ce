import type { ReactNode } from "react";
import { ChevronDown, FilterLines, Plus } from "@untitledui/icons";
import { Dialog as AriaDialog, DialogTrigger as AriaDialogTrigger, Popover as AriaPopover } from "react-aria-components";
import { Button } from "@/components/base/buttons/button";
import { CloseButton } from "@/components/base/buttons/close-button";
import { cx } from "@/utils/cx";

export interface FilterRow {
    id: string;
    field: string;
    operator: string;
    value: string;
}

export interface FilterDialogProps {
    /** The filter rows currently in the dialog */
    filters: FilterRow[];
    /** Called when "Apply filter" is clicked */
    onApply?: (filters: FilterRow[]) => void;
    /** Called when "Clear all" is clicked */
    onClearAll?: () => void;
    /** Called when "Add filter" is clicked */
    onAddFilter?: () => void;
    /** Called when a filter row is removed */
    onRemoveFilter?: (id: string) => void;
    /** Called when a filter row changes */
    onFilterChange?: (id: string, patch: Partial<Omit<FilterRow, "id">>) => void;
    /** Render function for a single filter row's inputs */
    renderFilterRow: (filter: FilterRow, onChange: (patch: Partial<Omit<FilterRow, "id">>) => void) => ReactNode;
    /** Additional class name */
    className?: string;
}

const FilterRowItem = ({ children, onRemove }: { children: ReactNode; onRemove?: () => void }) => (
    <div className="flex items-start gap-1">
        <div className="flex min-w-0 flex-1 items-center gap-3">{children}</div>
        {/* slot={null} opts out of the default "close" slot so removing a row doesn't also close the dialog. */}
        <CloseButton label="Remove filter" size="sm" slot={null} onPress={onRemove} />
    </div>
);

export const FilterDialog = ({ filters, onApply, onClearAll, onAddFilter, onRemoveFilter, onFilterChange, renderFilterRow, className }: FilterDialogProps) => {
    const hasFilters = filters.length > 0;

    return (
        <AriaDialog className={cx("overflow-hidden rounded-lg bg-primary shadow-lg ring-1 ring-secondary_alt outline-hidden", className)}>
            {({ close }) =>
                !hasFilters ? (
                    <div className="flex flex-col gap-3 p-4">
                        <div className="flex max-w-[352px] flex-col gap-1 text-sm">
                            <p className="font-semibold text-primary">No filters applied</p>
                            <p className="font-normal text-tertiary">Add filters to narrow down results.</p>
                        </div>
                        <div>
                            <Button size="xs" color="secondary" iconLeading={Plus} onClick={onAddFilter}>
                                Add filter
                            </Button>
                        </div>
                    </div>
                ) : (
                    <>
                        <div className="flex flex-col gap-3 p-4">
                            <div className="flex flex-col gap-3">
                                {filters.map((filter) => (
                                    <FilterRowItem key={filter.id} onRemove={() => onRemoveFilter?.(filter.id)}>
                                        {renderFilterRow(filter, (patch) => onFilterChange?.(filter.id, patch))}
                                    </FilterRowItem>
                                ))}
                            </div>
                        </div>

                        <div className="flex items-center justify-between border-t border-secondary px-4 py-3">
                            <Button size="xs" color="secondary" iconLeading={Plus} onClick={onAddFilter}>
                                Add filter
                            </Button>
                            <div className="flex items-center gap-3">
                                <Button size="xs" color="secondary" onClick={() => onClearAll?.()}>
                                    Clear all
                                </Button>
                                <Button
                                    size="xs"
                                    color="primary"
                                    onClick={() => {
                                        onApply?.(filters);
                                        close();
                                    }}
                                >
                                    Apply filter
                                </Button>
                            </div>
                        </div>
                    </>
                )
            }
        </AriaDialog>
    );
};

export interface FilterDropdownProps extends FilterDialogProps {
    /** Number of applied (committed) filters to show in the badge. Only used by the default trigger. */
    appliedCount?: number;
    /** Whether the trigger is disabled. Only used by the default trigger. */
    isDisabled?: boolean;
    /** Popover placement relative to trigger */
    placement?: "bottom" | "bottom start" | "bottom end";
    /** Custom trigger element. When provided, replaces the default "Filters" button. */
    children?: ReactNode;
}

export const CountBadge = ({ count, className }: { count: number; className?: string }) => (
    <span
        className={cx(
            "inline-flex items-center rounded-md border border-primary bg-primary px-1.5 py-0.5 text-xs leading-[18px] font-medium text-secondary shadow-xs",
            className,
        )}
    >
        {count}
    </span>
);

export const FilterDropdown = ({
    filters,
    appliedCount,
    onApply,
    onClearAll,
    onAddFilter,
    onRemoveFilter,
    onFilterChange,
    renderFilterRow,
    isDisabled,
    className,
    placement = "bottom end",
    children,
}: FilterDropdownProps) => {
    const hasFilters = filters.length > 0;
    const hasApplied = appliedCount != null && appliedCount > 0;

    return (
        <AriaDialogTrigger>
            {children ?? (
                <Button
                    color="secondary"
                    size="sm"
                    iconLeading={FilterLines}
                    iconTrailing={ChevronDown}
                    isDisabled={isDisabled}
                    className={cx("max-h-9", hasApplied && "bg-primary_hover", className)}
                >
                    <span className="flex items-center gap-1.5">
                        Filters
                        {hasApplied && <CountBadge count={appliedCount} />}
                    </span>
                </Button>
            )}
            <AriaPopover
                placement={placement}
                offset={4}
                containerPadding={0}
                className={(state) =>
                    cx(
                        "origin-(--trigger-anchor-point) will-change-transform md:w-[624px]",
                        state.isEntering &&
                            "duration-150 ease-out animate-in fade-in placement-top:slide-in-from-bottom-0.5 placement-bottom:slide-in-from-top-0.5",
                        state.isExiting &&
                            "duration-100 ease-in animate-out fade-out placement-top:slide-out-to-bottom-0.5 placement-bottom:slide-out-to-top-0.5",
                        !hasFilters && "w-[280px]",
                    )
                }
            >
                <FilterDialog
                    filters={filters}
                    onApply={onApply}
                    onClearAll={onClearAll}
                    onAddFilter={onAddFilter}
                    onRemoveFilter={onRemoveFilter}
                    onFilterChange={onFilterChange}
                    renderFilterRow={renderFilterRow}
                />
            </AriaPopover>
        </AriaDialogTrigger>
    );
};
