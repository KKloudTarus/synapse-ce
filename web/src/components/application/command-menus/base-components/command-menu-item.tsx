import type { FC } from "react";
import { Text as AriaText, ListBoxItem, type ListBoxItemProps } from "react-aria-components";
import { Avatar } from "@/components/base/avatar/avatar";
import { FeaturedIcon } from "@/components/foundations/featured-icon/featured-icon";
import { cx } from "@/utils/cx";
import { CommandShortcut } from "./command-shortcut";

interface CommandMenuItemBaseType {
    id: string;
    label: string;
    description?: string;
    stacked?: boolean;
    shortcutKeys?: string[];
}

interface CommandDropdownMenuItemDefaultType extends CommandMenuItemBaseType {
    type?: "default";
}

interface CommandDropdownMenuItemIconType extends CommandMenuItemBaseType {
    type: "icon";
    icon: FC<{ className?: string }>;
}

interface CommandDropdownMenuItemAvatarType extends CommandMenuItemBaseType {
    type: "avatar";
    src: string;
    alt: string;
}

interface CommandDropdownMenuItemDotType extends CommandMenuItemBaseType {
    type: "dot";
    dotColor: "green";
}

export type CommandDropdownMenuItemType =
    | CommandDropdownMenuItemDefaultType
    | CommandDropdownMenuItemIconType
    | CommandDropdownMenuItemAvatarType
    | CommandDropdownMenuItemDotType;

// Omit keys from an object
function omit(obj: object, keys: string[]): object {
    const keysToOmit = new Set(keys);
    return Object.fromEntries(Object.entries(obj).filter(([key]) => !keysToOmit.has(key)));
}

export type CommandDropdownMenuItemProps = CommandDropdownMenuItemType & ListBoxItemProps;

export const CommandDropdownMenuItem = ({ label, children, description, stacked, shortcutKeys, className, ...props }: CommandDropdownMenuItemProps) => {
    return (
        <ListBoxItem
            {...omit(props, ["type", "icon", "alt", "src"])}
            textValue={label}
            className={(state) => cx("group block cursor-pointer px-2 py-0.5 outline-hidden", typeof className === "function" ? className(state) : className)}
        >
            {(state) => (
                <div
                    className={cx(
                        "relative flex min-h-10 items-center justify-between rounded-lg px-2.5 py-2 pl-2.5 outline-focus-ring transition duration-100 ease-linear hover:bg-primary_hover",
                        state.isSelected && "bg-primary_hover",
                        state.isFocusVisible && "outline-2 outline-offset-2",
                        stacked && "items-start p-2.5 pl-3.5",
                    )}
                >
                    {props.type === "icon" && !stacked && <props.icon className="mr-2 size-5 text-fg-quaternary" />}
                    {props.type === "icon" && stacked && <FeaturedIcon color="gray" size="md" theme="modern" icon={props.icon} className="mr-2" />}

                    {props.type === "avatar" && <Avatar alt={props.alt} src={props.src} size={stacked ? "md" : "xs"} className="mr-2" />}

                    {props.type === "dot" && (
                        <svg
                            width="10"
                            height="10"
                            viewBox="0 0 10 10"
                            fill="none"
                            className={cx("mr-2 shrink-0 text-fg-success-secondary", stacked && "mt-2 self-start")}
                        >
                            <circle cx="5" cy="5" r="4" fill="currentColor" />
                        </svg>
                    )}

                    <div className={cx("flex flex-1 gap-x-1.5", stacked && "flex-col")}>
                        <AriaText slot="label" className="text-sm font-medium text-primary">
                            {typeof children === "function" ? children(state) : children || label}
                        </AriaText>
                        {description && (
                            <AriaText slot="description" className="text-sm text-tertiary">
                                {description}
                            </AriaText>
                        )}
                    </div>

                    {shortcutKeys && <CommandShortcut keys={shortcutKeys} />}
                </div>
            )}
        </ListBoxItem>
    );
};
