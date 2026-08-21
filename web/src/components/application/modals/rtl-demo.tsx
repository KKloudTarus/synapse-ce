import { useState } from "react";
import { CheckCircle } from "@untitledui/icons";
import { I18nProvider } from "react-aria";
import type { Key } from "react-aria-components";
import { Tabs } from "@/components/application/tabs/tabs";
import { Button } from "@/components/base/buttons/button";
import { CloseButton } from "@/components/base/buttons/close-button";
import { Toggle } from "@/components/base/toggle/toggle";
import { FeaturedIcon } from "@/components/foundations/featured-icon/featured-icon";

const translations = {
    en: {
        locale: "en",
        direction: "ltr" as const,
        title: "Blog post published",
        description: "This blog post has been published. Team members will be able to edit this post and republish changes.",
        shareTwitter: "Share on X",
        shareMedium: "Share on Medium",
        shareFacebook: "Share on Facebook",
        cancel: "Cancel",
        confirm: "Confirm",
    },
    ar: {
        locale: "ar",
        direction: "rtl" as const,
        title: "تم نشر المقال",
        description: "تم نشر هذا المقال بنجاح. سيتمكن أعضاء الفريق من تعديل هذا المقال وإعادة نشر التغييرات.",
        shareTwitter: "مشاركة على إكس",
        shareMedium: "مشاركة على ميديوم",
        shareFacebook: "مشاركة على فيسبوك",
        cancel: "إلغاء",
        confirm: "تأكيد",
    },
};

const langTabs = [
    { id: "en", label: "English" },
    { id: "ar", label: "Arabic" },
];

export const RtlDemo = () => {
    const [lang, setLang] = useState<Key>("en");
    const t = translations[lang as "en" | "ar"];

    return (
        <div className="flex flex-col gap-4">
            <Tabs selectedKey={lang} onSelectionChange={setLang} className="w-max">
                <Tabs.List type="button-minimal" items={langTabs}>
                    {(tab) => <Tabs.Item {...tab} />}
                </Tabs.List>
            </Tabs>

            <I18nProvider locale={t.locale}>
                <div dir={t.direction} className="flex min-h-120 items-center justify-center rounded-[20px] bg-secondary p-6 ring-1 ring-secondary ring-inset">
                    <div className="w-full max-w-100 overflow-hidden rounded-2xl bg-primary shadow-xl ring-1 ring-secondary_alt">
                        <div className="relative">
                            <CloseButton theme="light" size="sm" className="absolute end-3 top-3 sm:end-4 sm:top-4" />
                            <div className="flex flex-col gap-4 px-4 pt-5 sm:px-6 sm:pt-6">
                                <div className="relative w-max">
                                    <CheckCircle
                                        style={{
                                            ":dir(rtl)": {
                                                transform: "scaleX(-1)",
                                            },
                                        }}
                                        className="size-10 text-success-primary"
                                    />
                                </div>
                                <div className="relative flex flex-col gap-0.5">
                                    <p className="text-md font-semibold text-primary">{t.title}</p>
                                    <p className="text-sm text-tertiary">{t.description}</p>
                                </div>
                            </div>
                            <div className="h-5 w-full" />
                            <div className="relative flex flex-col gap-3 px-4 sm:px-6">
                                <Toggle key={`twitter-${lang}`} size="sm" label={t.shareTwitter} hint="@yourcompany" defaultSelected />
                                <Toggle key={`medium-${lang}`} size="sm" label={t.shareMedium} hint="yourcompany.medium.com" defaultSelected />
                                <Toggle key={`facebook-${lang}`} size="sm" label={t.shareFacebook} hint="@yourcompany" />
                            </div>
                            <div className="flex flex-1 flex-col-reverse gap-3 p-4 pt-6 *:grow sm:grid sm:grid-cols-2 sm:px-6 sm:pt-8 sm:pb-6">
                                <Button color="secondary" size="md">
                                    {t.cancel}
                                </Button>
                                <Button color="primary" size="md">
                                    {t.confirm}
                                </Button>
                            </div>
                        </div>
                    </div>
                </div>
            </I18nProvider>
        </div>
    );
};
