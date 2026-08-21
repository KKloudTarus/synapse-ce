import { useState } from "react";
import { Plus } from "@untitledui/icons";
import { Heading as AriaHeading } from "react-aria-components";
import { useHotkeys } from "react-hotkeys-hook";
import { CommandMenu } from "@/components/application/command-menus/command-menu";
import { EmptyState } from "@/components/application/empty-state/empty-state";
import { Button } from "@/components/base/buttons/button";

export const CommandMenuEmptyState = () => {
    const [isOpen, setIsOpen] = useState(true);
    const [inputValue, setInputValue] = useState("Landing page design");

    useHotkeys("meta+k", () => setIsOpen(true));

    return (
        <>
            <Button color="secondary" onClick={() => setIsOpen(true)}>
                Open Command Menu (⌘K)
            </Button>

            <CommandMenu
                isOpen={isOpen}
                items={[]}
                onInputChange={setInputValue}
                onOpenChange={setIsOpen}
                inputValue={inputValue}
                onSelectionChange={(keys) => console.log("You clicked item: ", keys)}
                emptyState={
                    <EmptyState size="sm" className="overflow-hidden p-6 pb-10">
                        <EmptyState.Header>
                            <EmptyState.FeaturedIcon color="gray" />
                        </EmptyState.Header>

                        <EmptyState.Content>
                            <EmptyState.Title>No projects found</EmptyState.Title>
                            <EmptyState.Description>Your search "{inputValue}" did not match any projects. Please try again.</EmptyState.Description>
                        </EmptyState.Content>

                        <EmptyState.Footer>
                            <Button size="md" color="secondary">
                                Clear search
                            </Button>
                            <Button size="md" iconLeading={Plus}>
                                New project
                            </Button>
                        </EmptyState.Footer>
                    </EmptyState>
                }
            >
                <AriaHeading slot="title" className="sr-only">
                    Projects
                </AriaHeading>
                <CommandMenu.List className="max-h-131.5 min-h-49" />
            </CommandMenu>
        </>
    );
};
