import type { ComponentPropsWithRef, ReactNode } from "react";
import { Children, Fragment, createContext, useContext, useMemo, useRef, useState } from "react";
import type { AutocompleteProps, DialogTriggerProps, Key, ListBoxProps, ListBoxSectionProps, ModalOverlayProps } from "react-aria-components";
import {
    Autocomplete as AriaAutocomplete,
    Collection as AriaCollection,
    Dialog as AriaDialog,
    DialogTrigger as AriaDialogTrigger,
    ListBox as AriaListBox,
    ListBoxSection as AriaListBoxSection,
    Modal as AriaModal,
    ModalOverlay as AriaModalOverlay,
    TextField as AriaTextField,
    useFilter,
} from "react-aria-components";
import { useHotkeys } from "react-hotkeys-hook";
import { cx } from "@/utils/cx";
import { CommandInput } from "./base-components/command-input";
import { CommandMenuFooter } from "./base-components/command-menu-footer";
import { CommandMenuHeader } from "./base-components/command-menu-header";
import { CommandDropdownMenuItem, type CommandDropdownMenuItemProps } from "./base-components/command-menu-item";
import { parseHotkey } from "./parseHotkeys";
import { isDeepEqual, mergeRefs } from "./utils";

export type CommandMenuGroupType = { id: string; title?: string; items: CommandDropdownMenuItemProps[] };

interface CommandMenuContextType extends Omit<CommandMenuRootProps, "children"> {
    /**
     * Whether the command menu has a footer. Used for
     * adding an extra bottom padding to the list to account
     * for the absolutely positioned footer at the bottom.
     */
    hasFooter?: boolean;
    /**
     * The flattened items of the command menu.
     */
    flatItems: CommandDropdownMenuItemProps[];
    /**
     * The currently selected keys.
     */
    selectedKeys: Iterable<Key>;
    /**
     * The function to set the currently selected keys.
     */
    setSelectedKeys: (keys: Iterable<Key>) => void;
}

const CommandMenuContext = createContext<CommandMenuContextType>({
    hasFooter: false,
    flatItems: [],
    selectedKeys: new Set(),
    setSelectedKeys: () => {},
});

interface CommandMenuRootProps
    extends Omit<ListBoxProps<CommandMenuGroupType>, "children" | "selectedKeys" | "className">, Omit<AutocompleteProps, "filter">, DialogTriggerProps {
    placeholder?: string;
    emptyState?: ReactNode;
    dialogClassName?: ModalOverlayProps["className"];
    overlayClassName?: ModalOverlayProps["className"];
    items?: CommandMenuGroupType[];
    defaultItems?: CommandMenuGroupType[];
    sensitivity?: "base" | "accent" | "case" | "variant" | undefined;
    shortcut?: string | null;
    filter?: false | AutocompleteProps["filter"];
}

const CommandMenuRoot = ({
    items,
    children,
    dialogClassName,
    overlayClassName,
    filter,
    inputValue,
    defaultItems,
    onInputChange,
    onSelectionChange,
    sensitivity = "base",
    placeholder = "Search",
    defaultSelectedKeys,
    shortcut = "⌘/",
    ...otherProps
}: CommandMenuRootProps) => {
    const inputRef = useRef<HTMLInputElement>(null);
    const { contains } = useFilter({ sensitivity });

    const [selectedKeys, setSelectedKeys] = useState<Iterable<Key>>(defaultSelectedKeys ?? new Set());

    // Flatten the items and register hotkeys for items with shortcut keys.
    const resolvedItems = items ?? defaultItems ?? [];
    const flatItems = resolvedItems.reduce<CommandDropdownMenuItemProps[]>((acc, group) => [...acc, ...group.items], []);
    const itemsWithShortcutKeys = flatItems.filter((item) => item.shortcutKeys?.length);
    const itemsWithShortcutKeysFormatted = itemsWithShortcutKeys.map((item) => ({
        ...item,
        shortcutKeys: item.shortcutKeys!.map((key) => {
            if (key.startsWith("⌘")) return key.replace("⌘", key.length > 1 ? "meta+" : "meta");

            return key;
        }),
    }));

    // Register hotkeys for items with shortcut keys.
    const useHotkeysRef = useHotkeys(
        itemsWithShortcutKeysFormatted.map((item) => item.shortcutKeys!.join("+")),
        (keyboardEvent, hotkeysEvent) => {
            keyboardEvent.preventDefault();

            const item = itemsWithShortcutKeysFormatted.find((option) => {
                const parsedHotkey = parseHotkey(option.shortcutKeys?.join("+"));

                return isDeepEqual(parsedHotkey, hotkeysEvent);
            });

            if (item) onSelectionChange?.(new Set([item.id]));
        },
        { enableOnFormTags: true },
    );

    // Register hotkey for input
    useHotkeys(shortcut?.split("").join("+").replace("⌘", "meta") ?? "", () => inputRef.current?.focus());

    // Determine if the command menu has a footer.
    const hasFooter = useMemo(() => {
        let hasFooter = false;

        Children.forEach(children, (child) => {
            if (child && typeof child === "object" && "type" in child && child.type === CommandMenuFooter) {
                hasFooter = true;
            }
        });

        return hasFooter;
    }, [children]);

    return (
        <CommandMenuContext.Provider value={{ hasFooter, flatItems, selectedKeys, setSelectedKeys, onSelectionChange, items, ...otherProps }}>
            <CommandDialog isOpen={otherProps.isOpen} onOpenChange={otherProps.onOpenChange} className={overlayClassName} dialogClassName={dialogClassName}>
                <AriaAutocomplete {...{ inputValue, onInputChange }} filter={filter === false ? undefined : filter || contains}>
                    <AriaTextField aria-label="Search">
                        <CommandInput
                            autoFocus
                            shortcutKeys={shortcut ? [shortcut] : undefined}
                            placeholder={placeholder}
                            ref={mergeRefs([inputRef, useHotkeysRef])}
                            className="relative outline-hidden! after:absolute after:bottom-0 after:left-0 after:h-px after:w-full after:bg-border-secondary"
                        />
                    </AriaTextField>
                    {children}
                </AriaAutocomplete>
            </CommandDialog>
        </CommandMenuContext.Provider>
    );
};

interface CommandMenuProps extends ModalOverlayProps {
    dialogClassName?: ModalOverlayProps["className"];
}

export const CommandDialog = ({ className, dialogClassName, children, ...comboboxProps }: CommandMenuProps) => {
    return (
        <AriaModalOverlay
            {...comboboxProps}
            isDismissable
            className={(state) =>
                cx(
                    "fixed inset-0 z-50 flex min-h-full items-start justify-center overflow-y-auto bg-overlay/70 p-4 text-center backdrop-blur md:pt-16 xl:pt-[clamp(64px,10vh,243px)]",
                    state.isEntering && "duration-300 ease-out animate-in fade-in",
                    state.isExiting && "duration-200 ease-in animate-out fade-out",
                    typeof className === "function" ? className(state) : className,
                )
            }
        >
            {(state) => (
                <AriaModal
                    className={(state) =>
                        cx(
                            "flex max-h-full w-160 flex-col overflow-hidden rounded-xl bg-primary text-left align-middle shadow-xl",
                            state.isEntering && "duration-300 ease-out animate-in zoom-in-95",
                            state.isExiting && "duration-200 ease-in animate-out zoom-out-95",
                            typeof dialogClassName === "function" ? dialogClassName(state) : dialogClassName,
                        )
                    }
                >
                    <AriaDialog aria-label="Command menu" className="relative flex min-h-0 flex-1 flex-col outline-hidden">
                        {typeof children === "function" ? children(state) : children}
                    </AriaDialog>
                </AriaModal>
            )}
        </AriaModalOverlay>
    );
};

interface CommandMenuListProps extends Omit<ListBoxProps<CommandMenuGroupType>, "items"> {}

export const CommandMenuList = ({ className, selectionMode = "single", ...props }: CommandMenuListProps) => {
    const { hasFooter, emptyState, ...listBoxProps } = useContext(CommandMenuContext);

    return (
        <AriaListBox
            aria-label="Command menu results"
            {...props}
            {...listBoxProps}
            renderEmptyState={() => emptyState}
            selectionMode={selectionMode}
            onSelectionChange={(key) => {
                listBoxProps.onSelectionChange?.(key as Set<Key>);
                listBoxProps.setSelectedKeys(key as Set<Key>);
            }}
            className={(state) =>
                cx(
                    "flex max-h-106 flex-1 scroll-py-10 flex-col gap-2 overflow-auto focus:outline-hidden",
                    hasFooter && "scroll-pb-22 pb-13",
                    !state.isEmpty && "pt-2",
                    typeof className === "function" ? className(state) : className,
                )
            }
        />
    );
};

interface CommandMenuSectionProps extends ListBoxSectionProps<CommandDropdownMenuItemProps> {
    title?: string;
}

export const CommandMenuSection = ({ title, children, items, ...props }: CommandMenuSectionProps) => {
    return (
        <AriaListBoxSection {...props} className={cx("border-b border-secondary pb-2 last:border-transparent", props.className)}>
            {title && (
                <CommandMenuHeader key={title} className="pb-1">
                    {title}
                </CommandMenuHeader>
            )}
            <AriaCollection items={items}>{children}</AriaCollection>
        </AriaListBoxSection>
    );
};

interface PreviewChildrenProps {
    /**
     * The unique identifier (`Key`) of the selected item.
     */
    selectedId: Key;
}

interface CommandMenuPreviewProps extends Omit<ComponentPropsWithRef<"div">, "children"> {
    asChild?: boolean;
    children: ({ selectedId }: PreviewChildrenProps) => ReactNode | ReactNode;
}

export const CommandMenuPreview = ({ children, asChild, ...props }: CommandMenuPreviewProps) => {
    const { selectedKeys } = useContext(CommandMenuContext);

    const keys = Array.from(selectedKeys);
    if (!keys.length) return null;

    const selectedId = keys.at(0) as Key;

    if (asChild) {
        return <Fragment>{typeof children === "function" ? children({ selectedId }) : children}</Fragment>;
    }

    return <div {...props}>{typeof children === "function" ? children({ selectedId }) : children}</div>;
};

export const CommandMenuGroup = ({ className, ...props }: ComponentPropsWithRef<"div">) => {
    return <div {...props} className={cx("min-h-0 flex-1", className)} />;
};

const CommandMenu = CommandMenuRoot as typeof CommandMenuRoot & {
    Item: typeof CommandDropdownMenuItem;
    List: typeof CommandMenuList;
    Group: typeof CommandMenuGroup;
    Footer: typeof CommandMenuFooter;
    Preview: typeof CommandMenuPreview;
    Section: typeof CommandMenuSection;
    Trigger: typeof AriaDialogTrigger;
    Collection: typeof AriaCollection;
};

CommandMenu.Item = CommandDropdownMenuItem;
CommandMenu.List = CommandMenuList;
CommandMenu.Group = CommandMenuGroup;
CommandMenu.Footer = CommandMenuFooter;
CommandMenu.Preview = CommandMenuPreview;
CommandMenu.Section = CommandMenuSection;
CommandMenu.Trigger = AriaDialogTrigger;
CommandMenu.Collection = AriaCollection;

export { CommandMenu };
