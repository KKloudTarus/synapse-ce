import { useState } from "react";
import { FilePlus03, Folder, FolderPlus, HelpCircle, LayersTwo02, User01, UserPlus01, Users01, ZapFast } from "@untitledui/icons";
import { Heading as AriaHeading } from "react-aria-components";
import { useHotkeys } from "react-hotkeys-hook";
import type { CommandDropdownMenuItemProps } from "@/components/application/command-menus/base-components/command-menu-item";
import { CommandMenu } from "@/components/application/command-menus/command-menu";
import { EmptyState } from "@/components/application/empty-state/empty-state";
import { Button } from "@/components/base/buttons/button";

const recentRoutes = [
    { id: "item-01", name: "Marketing site redesign", description: "Project by Olivia Rhye in Notion migration", icon: Folder },
    { id: "item-02", name: "New document", description: "Create a new blank document", icon: FilePlus03, shortcutKeys: ["⌘n"] },
    { id: "item-03", name: "Invite colleagues", description: "Collaborate with your team on projects", icon: UserPlus01, shortcutKeys: ["⌘i"] },
];

const routes = [
    { id: "route-01", name: "My profile", description: "View and edit your personal profile", icon: User01, shortcutKeys: ["⌘k", "p"] },
    { id: "route-02", name: "Team profile", description: "View and edit your team profile", icon: Users01, shortcutKeys: ["⌘k", "t"] },
    { id: "route-03", name: "Invite colleagues", description: "Collaborate with your team on projects", icon: UserPlus01, shortcutKeys: ["⌘i"] },
    { id: "route-04", name: "Create new project", description: "Create a new blank project", icon: FolderPlus, shortcutKeys: ["⌘n"] },
    { id: "route-05", name: "Support", description: "Our team are here to help if you get stuck", icon: HelpCircle, shortcutKeys: ["⌘h"] },
    { id: "route-06", name: "Changelog", description: "Learn about our latest releases and updates", icon: LayersTwo02, shortcutKeys: ["⌘c"] },
    { id: "route-07", name: "Keyboard shortcuts", description: "Speed up your workflow with shortcuts", icon: ZapFast, shortcutKeys: ["⌘?"] },
];

export const CommandMenuActionsStacked = () => {
    const [isOpen, setIsOpen] = useState(true);

    const recentItems: CommandDropdownMenuItemProps[] = recentRoutes.map((route) => ({
        id: route.id,
        type: "icon",
        label: route.name,
        icon: route.icon,
        size: "sm",
        shortcutKeys: route.shortcutKeys,
        description: route.description,
        stacked: true,
    }));

    const items: CommandDropdownMenuItemProps[] = routes.map((route) => ({
        id: route.id,
        type: "icon",
        label: route.name,
        icon: route.icon,
        size: "sm",
        shortcutKeys: route.shortcutKeys,
        description: route.description,
        stacked: true,
    }));

    const groups = [
        { id: "recent", title: "Recent", items: recentItems },
        { id: "default", items },
    ];

    useHotkeys("meta+k", () => setIsOpen(true));

    return (
        <>
            <Button color="secondary" onClick={() => setIsOpen(true)}>
                Open Command Menu (⌘K)
            </Button>

            <CommandMenu
                isOpen={isOpen}
                items={groups}
                onOpenChange={setIsOpen}
                onSelectionChange={(key) => console.log("You clicked item: ", key.toString())}
                emptyState={
                    <EmptyState size="sm" className="overflow-hidden p-6 pb-10">
                        <EmptyState.Header>
                            <EmptyState.FeaturedIcon color="gray" />
                        </EmptyState.Header>

                        <EmptyState.Content className="mb-0">
                            <EmptyState.Title>No actions found</EmptyState.Title>
                            <EmptyState.Description>
                                Your search did not match any actions. <br />
                                Please try again.
                            </EmptyState.Description>
                        </EmptyState.Content>
                    </EmptyState>
                }
            >
                <AriaHeading slot="title" className="sr-only">
                    Actions
                </AriaHeading>
                <CommandMenu.Group>
                    <CommandMenu.List className="min-h-49">
                        {(group) => <CommandMenu.Section {...group}>{(item) => <CommandMenu.Item key={item.id} {...item} />}</CommandMenu.Section>}
                    </CommandMenu.List>
                </CommandMenu.Group>
            </CommandMenu>
        </>
    );
};
