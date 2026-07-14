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


REF = "https://developer.android.com/reference/"


# Java quality pack: deprecated Android framework APIs (batch 3).
RULES = [
    r(id="java-android-onbackpressed", title="onBackPressed override", desc="Activity.onBackPressed() is deprecated.",
      rationale="onBackPressed was deprecated in API 33 in favor of the predictive-back OnBackPressedDispatcher.", remediation="Register an OnBackPressedCallback.",
      source=REF + "androidx/activity/OnBackPressedDispatcher", re=r"void\s+onBackPressed\s*\(\s*\)", nc="public void onBackPressed() {", c="// register an OnBackPressedCallback"),
    r(id="java-android-getrunningtasks", title="ActivityManager.getRunningTasks", desc="getRunningTasks() is deprecated.",
      rationale="getRunningTasks was deprecated in API 21; apps can only see their own tasks.", remediation="Use getAppTasks() for your own tasks.",
      source=REF + "android/app/ActivityManager", re=r"\.getRunningTasks\s*\(", nc="am.getRunningTasks(1);", c="am.getAppTasks();"),
    r(id="java-android-camera-import", title="Camera API import", desc="android.hardware.Camera is deprecated.",
      rationale="The android.hardware.Camera API was deprecated in API 21 in favor of Camera2/CameraX.", remediation="Use CameraX (androidx.camera).",
      source=REF + "android/hardware/Camera", re=r"import\s+android\.hardware\.Camera;", nc="import android.hardware.Camera;", c="import androidx.camera.core.ImageCapture;"),
    r(id="java-android-getactivenetworkinfo", title="getActiveNetworkInfo", desc="getActiveNetworkInfo() is deprecated.",
      rationale="getActiveNetworkInfo/NetworkInfo were deprecated in API 29.", remediation="Use getNetworkCapabilities on the active Network.",
      source=REF + "android/net/ConnectivityManager", re=r"getActiveNetworkInfo\s*\(", nc="NetworkInfo ni = cm.getActiveNetworkInfo();", c="NetworkCapabilities caps = cm.getNetworkCapabilities(cm.getActiveNetwork());"),
    r(id="java-android-getserializable-untyped", title="Bundle.getSerializable(String)", desc="The untyped getSerializable is deprecated.",
      rationale="The single-argument getSerializable(String) was deprecated in API 33 for a type-safe overload.", remediation="Pass the expected class: getSerializable(key, Type.class).",
      source=REF + "android/os/Bundle", re=r'\.getSerializable\s*\(\s*"[^"]*"\s*\)', nc='bundle.getSerializable("data");', c='bundle.getSerializable("data", Payload.class);'),
    r(id="java-android-getparcelable-untyped", title="Bundle.getParcelable(String)", desc="The untyped getParcelable is deprecated.",
      rationale="The single-argument getParcelable(String) was deprecated in API 33 for a type-safe overload.", remediation="Pass the expected class: getParcelable(key, Type.class).",
      source=REF + "android/os/Bundle", re=r'\.getParcelable\s*\(\s*"[^"]*"\s*\)', nc='bundle.getParcelable("user");', c='bundle.getParcelable("user", User.class);'),
    r(id="java-android-preferencefragment", title="PreferenceFragment subclass", desc="PreferenceFragment is deprecated.",
      rationale="The framework PreferenceFragment was deprecated in API 29 in favor of PreferenceFragmentCompat.", remediation="Extend androidx PreferenceFragmentCompat.",
      source=REF + "androidx/preference/PreferenceFragmentCompat", re=r"extends\s+PreferenceFragment\b", nc="class Settings extends PreferenceFragment {", c="class Settings extends PreferenceFragmentCompat {"),
]
