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


AND = "https://developer.android.com/reference/"


# Java quality pack: deprecated Android framework APIs.
RULES = [
    r(id="java-android-asynctask", title="AsyncTask subclass", desc="AsyncTask was deprecated in API level 30.",
      rationale="AsyncTask has lifecycle and cancellation pitfalls and is deprecated.", remediation="Use java.util.concurrent (Executor) or Kotlin coroutines.",
      source=AND + "android/os/AsyncTask", re=r"extends\s+AsyncTask\b", nc="class DownloadTask extends AsyncTask<Void, Void, String> {", c="// use an Executor or coroutines"),
    r(id="java-android-progressdialog", title="ProgressDialog", desc="ProgressDialog was deprecated in API level 26.",
      rationale="ProgressDialog blocks interaction and is deprecated.", remediation="Use an inline ProgressBar or a Material dialog.",
      source=AND + "android/app/ProgressDialog", re=r"new\s+ProgressDialog\s*\(", nc="new ProgressDialog(this);", c="// show an inline ProgressBar"),
    r(id="java-android-fingerprint-manager", title="FingerprintManager", desc="FingerprintManager was deprecated in API level 28.",
      rationale="FingerprintManager is deprecated in favor of the unified BiometricPrompt.", remediation="Use androidx.biometric.BiometricPrompt.",
      source=AND + "android/hardware/fingerprint/FingerprintManager", re=r"\bFingerprintManager\b", nc="FingerprintManager fm = getSystemService(FingerprintManager.class);", c="// use androidx.biometric.BiometricPrompt"),
    r(id="java-android-start-activity-for-result", title="startActivityForResult", desc="startActivityForResult was deprecated in API level 30.",
      rationale="startActivityForResult/onActivityResult are deprecated in favor of the Activity Result APIs.", remediation="Use registerForActivityResult.",
      source=AND + "androidx/activity/result/ActivityResultLauncher", re=r"startActivityForResult\s*\(", nc="startActivityForResult(intent, REQUEST_CODE);", c="launcher.launch(intent);"),
    r(id="java-android-on-activity-result", title="onActivityResult override", desc="onActivityResult was deprecated in API level 30.",
      rationale="Overriding onActivityResult is deprecated in favor of the Activity Result callback.", remediation="Register an ActivityResultCallback.",
      source=AND + "androidx/activity/result/ActivityResultCallback", re=r"void\s+onActivityResult\s*\(", nc="protected void onActivityResult(int requestCode, int resultCode, Intent data) {", c="// register an ActivityResultCallback"),
    r(id="java-android-preferencemanager-default", title="PreferenceManager.getDefaultSharedPreferences", desc="The framework PreferenceManager was deprecated in API level 29.",
      rationale="android.preference.PreferenceManager is deprecated.", remediation="Use Jetpack DataStore or androidx.preference.",
      source=AND + "android/preference/PreferenceManager", re=r"PreferenceManager\.getDefaultSharedPreferences", nc="PreferenceManager.getDefaultSharedPreferences(context);", c="// migrate to Jetpack DataStore"),
    r(id="java-android-get-imei", type="hotspot", qual="sec", sev="medium", cwe="CWE-200", owasp="A01:2021",
      title="TelephonyManager.getImei", desc="Reading the IMEI accesses a persistent hardware identifier.",
      rationale="The IMEI is a non-resettable identifier; reading it is privacy-sensitive and restricted on modern Android.",
      remediation="Use a resettable, app-scoped identifier instead.",
      source=AND + "android/telephony/TelephonyManager", re=r"\.getImei\s*\(", nc="String imei = tm.getImei();", c="// use an app-scoped UUID stored in preferences"),
]
