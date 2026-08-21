import { useState } from "react";
import { Heading as AriaHeading } from "react-aria-components";
import { useHotkeys } from "react-hotkeys-hook";
import type { CommandDropdownMenuItemProps } from "@/components/application/command-menus/base-components/command-menu-item";
import { CommandMenu } from "@/components/application/command-menus/command-menu";
import { EmptyState } from "@/components/application/empty-state/empty-state";
import { Button } from "@/components/base/buttons/button";
import { Toggle } from "@/components/base/toggle/toggle";
import { cx } from "@/utils/cx";

const integrations = [
    {
        id: "integration-01",
        name: "GitHub",
        website: "github.com",
        description: "Connect your GitHub account to access your repositories",
        imageSrc: "https://www.untitledui.com/logos/integrations/github.svg",
    },
    {
        id: "integration-02",
        name: "Linear",
        website: "linear.app",
        description: "Linear helps streamline software projects, sprints, tasks, and bug tracking.",
        imageSrc: "https://www.untitledui.com/logos/integrations/linear.svg",
    },
    {
        id: "integration-03",
        name: "Figma",
        website: "figma.com",
        description: "Figma is a collaborative interface design tool",
        imageSrc: "https://www.untitledui.com/logos/integrations/figma.svg",
    },
    {
        id: "integration-04",
        name: "Zapier",
        website: "zapier.com",
        description: "Connect your apps and automate workflows",
        imageSrc: "https://www.untitledui.com/logos/integrations/zapier.svg",
    },
    {
        id: "integration-05",
        name: "Notion",
        website: "notion.so",
        description: "All-in-one workspace for notes, tasks, wikis, and databases",
        imageSrc: "https://www.untitledui.com/logos/integrations/notion.svg",
    },
    {
        id: "integration-06",
        name: "Slack",
        website: "slack.com",
        description: "Slack is a new way to communicate with your team",
        imageSrc: "https://www.untitledui.com/logos/integrations/slack.svg",
    },
    {
        id: "integration-07",
        name: "Dropbox",
        website: "dropbox.com",
        description: "Dropbox is a file hosting service",
        imageSrc: "https://www.untitledui.com/logos/integrations/dropbox.svg",
    },
];

const IntegrationPreview = ({ title, imageSrc, description, className }: { title: string; imageSrc: string; description: string; className?: string }) => (
    <div className={cx("relative flex w-90 flex-col border-l border-secondary bg-primary px-5 py-6", className)}>
        <div className="mb-3 flex justify-between">
            <img src={imageSrc} alt={title} className="size-16" />
            <Toggle defaultSelected size="sm" className="mt-0.5" />
        </div>
        <div className="flex w-full flex-col gap-6">
            <div className="flex flex-col gap-0.5">
                <p className="text-md font-semibold text-primary">{title}</p>
                <p className="text-sm text-tertiary">{description}</p>
            </div>
            <div className="flex w-full flex-col justify-center gap-3">
                <Button size="md">View integration</Button>
                <Button size="md" color="secondary">
                    Learn more
                </Button>
            </div>
        </div>
    </div>
);

export const CommandMenuIntegrationsMenuStacked = () => {
    const [isOpen, setIsOpen] = useState(true);

    const items: CommandDropdownMenuItemProps[] = integrations.map((integration) => ({
        type: "avatar",
        id: integration.id,
        label: integration.name,
        description: integration.website,
        src: integration.imageSrc,
        info: integration.description,
        alt: integration.name,
    }));

    const groups = [{ id: "integrations", title: "Integrations", items }];

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
                            <EmptyState.Title>No integrations found</EmptyState.Title>
                            <EmptyState.Description>
                                Your search did not match any integrations. <br />
                                Please try again.
                            </EmptyState.Description>
                        </EmptyState.Content>
                    </EmptyState>
                }
            >
                <AriaHeading slot="title" className="sr-only">
                    Integrations
                </AriaHeading>
                <CommandMenu.Group className="flex max-h-96">
                    <CommandMenu.List>
                        {(group) => (
                            <CommandMenu.Section {...group}>
                                {(item) => (
                                    <CommandMenu.Item
                                        stacked
                                        key={item.id}
                                        className="**:data-avatar:rounded-none **:data-avatar:bg-transparent **:data-avatar:outline-hidden **:data-avatar-img:rounded-none"
                                        {...item}
                                    />
                                )}
                            </CommandMenu.Section>
                        )}
                    </CommandMenu.List>
                    <CommandMenu.Preview asChild>
                        {({ selectedId }) => {
                            const integration = integrations.find((integration) => integration.id === selectedId) as (typeof integrations)[number];

                            return <IntegrationPreview title={integration?.name} description={integration?.description} imageSrc={integration?.imageSrc} />;
                        }}
                    </CommandMenu.Preview>
                </CommandMenu.Group>
            </CommandMenu>
        </>
    );
};
