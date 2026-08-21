import { useState } from "react";
import { Plus } from "@untitledui/icons";
import { Heading as AriaHeading } from "react-aria-components";
import { useHotkeys } from "react-hotkeys-hook";
import type { CommandDropdownMenuItemType } from "@/components/application/command-menus/base-components/command-menu-item";
import { CommandMenu } from "@/components/application/command-menus/command-menu";
import { EmptyState } from "@/components/application/empty-state/empty-state";
import { AvatarProfilePhoto } from "@/components/base/avatar/avatar-profile-photo";
import { Button } from "@/components/base/buttons/button";
import { Dribbble, LinkedIn, X } from "@/components/foundations/social-icons";
import { cx } from "@/utils/cx";

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

const UsersMenuPreview = ({
    title,
    description,
    size = "sm",
    imageSrc,
    className,
}: {
    title: string;
    description: string;
    imageSrc: string;
    className?: string;
    size?: "sm" | "md";
}) => {
    return (
        <div className={cx("relative flex w-90 flex-col items-center border-l border-secondary bg-primary", className)}>
            <div className="w-full px-1 pt-1">
                <div className={cx("w-full rounded-xl bg-linear-to-t from-[#FBC5EC] to-[#A5C0EE]", size === "sm" ? "h-22" : "h-28")} />
            </div>

            <div className="relative -mt-8 w-full max-w-(--breakpoint-xl) px-4">
                <div className="relative flex flex-col items-center gap-4">
                    <AvatarProfilePhoto size="sm" src={imageSrc} alt={title} verified />
                    <div className="flex w-full flex-col items-center gap-4">
                        <div className="flex flex-col items-center gap-0.5 text-center">
                            <p className="text-md font-semibold text-primary">{title}</p>
                            <p className="text-sm text-tertiary">{description}</p>
                        </div>
                        <ul className="flex gap-4">
                            {[
                                { title: "X", href: "https://x.com/", icon: X },
                                { title: "LinkedIn", href: "https://linkedin.com/", icon: LinkedIn },
                                { title: "Dribbble", href: "https://dribbble.com/", icon: Dribbble },
                            ].map(({ title, href, icon: Icon }) => (
                                <li key={title}>
                                    <a
                                        href={href}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="flex rounded-xs text-fg-quaternary outline-focus-ring transition duration-100 ease-linear hover:text-fg-quaternary_hover focus-visible:outline-2 focus-visible:outline-offset-2"
                                    >
                                        <Icon size={20} aria-label={title} />
                                    </a>
                                </li>
                            ))}
                        </ul>
                        <div className="flex w-full justify-center gap-3 pt-2">
                            <Button color="secondary" size="md" className="flex-1 sm:flex-none">
                                View portfolio
                            </Button>
                            <Button iconLeading={Plus} size="md" className="flex-1 sm:flex-none">
                                Follow
                            </Button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
};

export const CommandMenuUsersMenu = () => {
    const [isOpen, setIsOpen] = useState(true);

    const items: CommandDropdownMenuItemType[] = people.map((person) => ({
        id: person.id,
        type: "avatar",
        label: person.name,
        src: person.imageSrc,
        alt: person.name,
        description: person.username,
        size: "sm",
        anything: "else",
    }));

    const groups = [{ id: "designers", title: "Designers", items: items }];

    useHotkeys("meta+k", () => setIsOpen(true));

    return (
        <>
            <Button color="secondary" onClick={() => setIsOpen(true)}>
                Open Command Menu (⌘K)
            </Button>

            <CommandMenu
                isOpen={isOpen}
                items={groups}
                defaultSelectedKeys={[groups[0].items[1].id]}
                onOpenChange={setIsOpen}
                onSelectionChange={(keys) => console.log("You clicked item: ", keys)}
                emptyState={
                    <EmptyState size="sm" className="overflow-hidden p-6 pb-10">
                        <EmptyState.Header>
                            <EmptyState.FeaturedIcon color="gray" />
                        </EmptyState.Header>

                        <EmptyState.Content className="mb-0">
                            <EmptyState.Title>No users found</EmptyState.Title>
                            <EmptyState.Description>Your search did not match any users. Please try again.</EmptyState.Description>
                        </EmptyState.Content>
                    </EmptyState>
                }
            >
                <AriaHeading slot="title" className="sr-only">
                    Users
                </AriaHeading>
                <CommandMenu.Group className="flex max-h-88.5">
                    <CommandMenu.List>
                        {(group) => <CommandMenu.Section {...group}>{(item) => <CommandMenu.Item key={item.id} {...item} />}</CommandMenu.Section>}
                    </CommandMenu.List>
                    <CommandMenu.Preview asChild>
                        {({ selectedId }) => {
                            const person = people.find((person) => person.id === selectedId) as (typeof people)[number];

                            return (
                                <UsersMenuPreview
                                    title={person?.name}
                                    description="I'm a Product Designer and Webflow Developer based in Melbourne, Australia."
                                    imageSrc={person?.imageSrc}
                                />
                            );
                        }}
                    </CommandMenu.Preview>
                </CommandMenu.Group>
            </CommandMenu>
        </>
    );
};
