import type { HTMLAttributes } from "react";
import { cx } from "@/utils/cx";
import { PlayIcon } from "./icons";

/**
 * Rounded play icon with blurred background and a filled triangle in the middle.
 */
export const PlayButtonIcon = (props: HTMLAttributes<HTMLDivElement>) => {
    return (
        <div
            {...props}
            className={cx(
                "flex size-20 items-center justify-center rounded-full bg-alpha-white/30 backdrop-blur transition duration-100 ease-linear group-hover:bg-alpha-white/50 hover:bg-alpha-white/50",
                props.className,
            )}
        >
            <PlayIcon className="size-5 text-white" />
        </div>
    );
};
