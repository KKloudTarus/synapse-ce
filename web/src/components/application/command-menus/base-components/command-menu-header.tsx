import type { ReactNode } from "react";
import { Header as AriaHeader } from "react-aria-components";
import { cx } from "@/utils/cx";

interface CommandMenuHeaderProps {
    children: ReactNode;
    className?: string;
}

export const CommandMenuHeader = ({ children: title, className }: CommandMenuHeaderProps) => {
    return <AriaHeader className={cx("flex px-4.5 pt-2 text-xs font-semibold text-tertiary", className)}>{title}</AriaHeader>;
};
