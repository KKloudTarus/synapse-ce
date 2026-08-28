import type { ComponentPropsWithRef, FC, ReactNode } from "react";
import { XClose } from "@untitledui/icons";
import { Button as AriaButton } from "react-aria-components";
import { cx } from "@/utils/cx";

interface FilterBarRootProps extends ComponentPropsWithRef<"div"> {
    /** Content and actions for the filter bar */
    children: ReactNode;
}

/** Root layout container for the filter bar. Arranges content and actions horizontally with wrapping. */
const FilterBarRoot = ({ children, className, ...props }: FilterBarRootProps) => (
    <div {...props} className={cx("flex flex-wrap items-end gap-3", className)}>
        {children}
    </div>
);

interface FilterBarContentProps extends ComponentPropsWithRef<"div"> {
    /** Filter inputs, tabs, or other content */
    children: ReactNode;
}

/** Left content area of the filter bar. Grows to fill available space. */
const FilterBarContent = ({ children, className, ...props }: FilterBarContentProps) => (
    <div {...props} className={cx("flex min-w-0 flex-1 flex-wrap items-end gap-3", className)}>
        {children}
    </div>
);

interface FilterBarActionsProps extends ComponentPropsWithRef<"div"> {
    /** Action buttons such as date picker, filters, search */
    children: ReactNode;
}

/** Right actions area of the filter bar. Shrinks to fit content. */
const FilterBarActions = ({ children, className, ...props }: FilterBarActionsProps) => (
    <div {...props} className={cx("flex shrink-0 items-center gap-3", className)}>
        {children}
    </div>
);

interface FilterRowProps extends ComponentPropsWithRef<"div"> {
    /** Filter field, operator, and value inputs */
    children: ReactNode;
    /** Callback when the remove button is clicked */
    onRemove?: () => void;
}

/** A single advanced filter row with inputs and a remove button. */
const FilterRow = ({ children, onRemove, className, ...props }: FilterRowProps) => (
    <div {...props} className={cx("flex items-start gap-1", className)}>
        <div className="flex items-center gap-3">{children}</div>
        <AriaButton
            aria-label="Remove filter"
            onPress={onRemove}
            className="flex size-9 shrink-0 cursor-pointer items-center justify-center rounded-lg text-fg-quaternary transition duration-100 ease-linear hover:text-fg-quaternary_hover"
        >
            <XClose className="size-5" />
        </AriaButton>
    </div>
);

interface FilterIconButtonProps {
    /** Icon component to render */
    icon: FC<{ className?: string }>;
    /** Accessible label */
    label?: string;
    /** Click handler */
    onPress?: () => void;
    /** Additional class names */
    className?: string;
}

/** Icon-only button styled to match filter bar controls (secondary button appearance). */
const FilterIconButton = ({ icon: Icon, label, onPress, className }: FilterIconButtonProps) => (
    <AriaButton
        aria-label={label}
        onPress={onPress}
        className={cx(
            "flex size-9 cursor-pointer items-center justify-center rounded-lg border border-primary bg-primary shadow-xs transition duration-100 ease-linear hover:bg-primary_hover",
            className,
        )}
    >
        <Icon className="size-5 text-fg-quaternary" />
    </AriaButton>
);

export const FilterBar = {
    Root: FilterBarRoot,
    Content: FilterBarContent,
    Actions: FilterBarActions,
    FilterRow,
    FilterIconButton,
};
