CC = "commentOnlyLine"


def r(**k):
    k.setdefault("lang", "java")
    k.setdefault("owasp", "")
    k.setdefault("effort", 30)
    k.setdefault("tags", ["sast", "java", "android"])
    k.setdefault("cat_desc", k["desc"])
    k.setdefault("skip", CC)
    k.setdefault("type", "smell")
    k.setdefault("qual", "maint")
    k.setdefault("sev", "low")
    k.setdefault("cwe", "")
    return k


AND = "https://developer.android.com/jetpack/androidx/migrate"
REF = "https://developer.android.com/reference/"


# Java quality pack: deprecated Android framework APIs (batch 2).
RULES = [
    r(id="java-android-support-library", title="android.support import", desc="The android.support.* libraries are superseded by AndroidX.",
      rationale="The legacy Support Library is frozen at 28.0.0; AndroidX is the maintained replacement.", remediation="Migrate to the androidx.* packages.",
      source=AND, re=r"import\s+android\.support\.", nc="import android.support.v4.app.Fragment;", c="import androidx.fragment.app.Fragment;"),
    r(id="java-android-actionbaractivity", title="ActionBarActivity subclass", desc="ActionBarActivity is deprecated.",
      rationale="ActionBarActivity was deprecated in favor of AppCompatActivity.", remediation="Extend AppCompatActivity.",
      source=REF + "androidx/appcompat/app/AppCompatActivity", re=r"extends\s+ActionBarActivity\b", nc="class Main extends ActionBarActivity {", c="class Main extends AppCompatActivity {"),
    r(id="java-android-listactivity", title="ListActivity subclass", desc="ListActivity is deprecated.",
      rationale="ListActivity is deprecated in favor of RecyclerView within a normal activity/fragment.", remediation="Use RecyclerView in an AppCompatActivity/Fragment.",
      source=REF + "android/app/ListActivity", re=r"extends\s+ListActivity\b", nc="class Items extends ListActivity {", c="class Items extends AppCompatActivity {"),
    r(id="java-android-tabactivity", title="TabActivity subclass", desc="TabActivity is deprecated.",
      rationale="TabActivity is deprecated in favor of fragments with a TabLayout.", remediation="Use TabLayout with a ViewPager2.",
      source=REF + "android/app/TabActivity", re=r"extends\s+TabActivity\b", nc="class Home extends TabActivity {", c="class Home extends AppCompatActivity {"),
    r(id="java-android-preferenceactivity", title="PreferenceActivity subclass", desc="PreferenceActivity is deprecated.",
      rationale="PreferenceActivity is deprecated in favor of androidx PreferenceFragmentCompat.", remediation="Use PreferenceFragmentCompat.",
      source=REF + "android/preference/PreferenceActivity", re=r"extends\s+PreferenceActivity\b", nc="class Settings extends PreferenceActivity {", c="class Settings extends AppCompatActivity {"),
    r(id="java-android-getdrawable-int", title="Resources.getDrawable(int)", desc="getResources().getDrawable(int) is deprecated.",
      rationale="The single-argument getDrawable(int) ignores the theme and is deprecated.", remediation="Use ContextCompat.getDrawable(context, id).",
      source=REF + "androidx/core/content/ContextCompat", re=r"getResources\s*\(\s*\)\s*\.getDrawable\s*\(", nc="getResources().getDrawable(R.drawable.ic);", c="ContextCompat.getDrawable(context, R.drawable.ic);"),
    r(id="java-android-getcolor-int", title="Resources.getColor(int)", desc="getResources().getColor(int) is deprecated.",
      rationale="The single-argument getColor(int) ignores the theme and is deprecated.", remediation="Use ContextCompat.getColor(context, id).",
      source=REF + "androidx/core/content/ContextCompat", re=r"getResources\s*\(\s*\)\s*\.getColor\s*\(", nc="getResources().getColor(R.color.primary);", c="ContextCompat.getColor(context, R.color.primary);"),
    r(id="java-android-html-fromhtml-legacy", title="Html.fromHtml(String)", desc="The one-argument Html.fromHtml is deprecated.",
      rationale="Html.fromHtml(String) was deprecated in API 24 because it has no way to specify legacy vs new flags.", remediation="Pass an explicit flag, e.g. Html.FROM_HTML_MODE_LEGACY.",
      source=REF + "android/text/Html", re=r"Html\.fromHtml\s*\(\s*[^,)]+\)", nc="Html.fromHtml(text);", c="Html.fromHtml(text, Html.FROM_HTML_MODE_LEGACY);"),
    r(id="java-android-vibrate-long", title="Vibrator.vibrate(long)", desc="Vibrator.vibrate(long) is deprecated.",
      rationale="vibrate(long) was deprecated in API 26 in favor of VibrationEffect.", remediation="Use VibrationEffect.createOneShot.",
      source=REF + "android/os/Vibrator", re=r"\.vibrate\s*\(\s*\d", nc="vibrator.vibrate(500);", c="vibrator.vibrate(VibrationEffect.createOneShot(500, DEFAULT_AMPLITUDE));"),
    r(id="java-android-notification-ctor", title="new Notification(...)", desc="The Notification constructor is deprecated.",
      rationale="Constructing a Notification directly is deprecated in favor of Notification.Builder with a channel.", remediation="Use NotificationCompat.Builder.",
      source=REF + "android/app/Notification", re=r"new\s+Notification\s*\(", nc="new Notification(icon, text, when);", c="new NotificationCompat.Builder(context, channelId).build();"),
    r(id="java-android-androidhttpclient", title="AndroidHttpClient", desc="AndroidHttpClient was removed in API 23.",
      rationale="AndroidHttpClient was deprecated then removed; the Apache HTTP client is no longer bundled.", remediation="Use HttpURLConnection or OkHttp.",
      source=REF + "android/net/http/AndroidHttpClient", re=r"\bAndroidHttpClient\b", nc="AndroidHttpClient client = AndroidHttpClient.newInstance(\"UA\");", c="// use HttpURLConnection or OkHttp"),
]
