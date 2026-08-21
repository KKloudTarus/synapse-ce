import { useState } from "react";
import { Heading as AriaHeading } from "react-aria-components";
import { useHotkeys } from "react-hotkeys-hook";
import type { CommandDropdownMenuItemProps } from "@/components/application/command-menus/base-components/command-menu-item";
import { CommandMenu } from "@/components/application/command-menus/command-menu";
import { EmptyState } from "@/components/application/empty-state/empty-state";
import { Button } from "@/components/base/buttons/button";

const people = [
    { id: "user-01", name: "Phoenix Baker", imageSrc: "https://www.untitledui.com/images/avatars/phoenix-baker?fm=webp&q=80", username: "@phoenix" },
    { id: "user-02", name: "Olivia Rhye", imageSrc: "https://www.untitledui.com/images/avatars/olivia-rhye?fm=webp&q=80", username: "@olivia" },
    { id: "user-03", name: "Lana Steiner", imageSrc: "https://www.untitledui.com/images/avatars/lana-steiner?fm=webp&q=80", username: "@lana" },
    { id: "user-04", name: "Demi Wilkinson", imageSrc: "https://www.untitledui.com/images/avatars/demi-wilkinson?fm=webp&q=80", username: "@demi" },
    { id: "user-05", name: "Candice Wu", imageSrc: "https://www.untitledui.com/images/avatars/candice-wu?fm=webp&q=80", username: "@candice" },
    { id: "user-06", name: "Natali Craig", imageSrc: "https://www.untitledui.com/images/avatars/natali-craig?fm=webp&q=80", username: "@natali" },
    { id: "user-07", name: "Drew Cano", imageSrc: "https://www.untitledui.com/images/avatars/drew-cano?fm=webp&q=80", username: "@drew" },
    { id: "user-08", name: "Kari Rasmussen", imageSrc: "https://www.untitledui.com/images/avatars/kari-rasmussen?fm=webp&q=80", username: "@kari" },
];

export const CommandMenuUsers = () => {
    const [isOpen, setIsOpen] = useState(true);

    const items: CommandDropdownMenuItemProps[] = people.map((person) => ({
        id: person.id,
        type: "avatar",
        label: person.name,
        src: person.imageSrc,
        alt: person.name,
        description: person.username,
        anything: "else",
        size: "sm",
    }));

    const groups = [
        { id: "recent", title: "Recent", items: items.slice(0, 2).map((item) => ({ ...item, id: item.id.concat("-recent") })) },
        { id: "all", title: "All users", items },
    ];

    useHotkeys("meta+k", () => setIsOpen(true));

    return (
        <>
            <Button color="secondary" onClick={() => setIsOpen(true)}>
                Open Command Menu (⌘K)
            </Button>

            <CommandMenu
                items={groups}
                isOpen={isOpen}
                onOpenChange={setIsOpen}
                onSelectionChange={(keys) => console.log("You clicked item: ", keys)}
                emptyState={
                    <EmptyState size="sm" className="overflow-hidden p-6 pb-10">
                        <EmptyState.Header>
                            <EmptyState.FeaturedIcon color="gray" />
                        </EmptyState.Header>

                        <EmptyState.Content className="mb-0">
                            <EmptyState.Title>No users found</EmptyState.Title>
                            <EmptyState.Description>
                                Your search did not match any users. <br />
                                Please try again.
                            </EmptyState.Description>
                        </EmptyState.Content>
                    </EmptyState>
                }
            >
                <AriaHeading slot="title" className="sr-only">
                    Users
                </AriaHeading>
                <CommandMenu.Group>
                    <CommandMenu.List className="min-h-49">
                        {(group) => <CommandMenu.Section {...group}>{(item) => <CommandMenu.Item key={item.id} {...item} />}</CommandMenu.Section>}
                    </CommandMenu.List>
                </CommandMenu.Group>
                <CommandMenu.Footer />
            </CommandMenu>
        </>
    );
};
