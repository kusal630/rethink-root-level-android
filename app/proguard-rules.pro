#
# ProGuard/R8 configuration for RethinkDNS (root level edition).
#
# Upstream's snapshot does not ship this file even though the `release`, `alpha` and
# `releaseDebug` build types all reference it, which makes every minified build fail with
# "Supplied proguard configuration does not exist". This file supplies the rules those
# builds need.
#
# Philosophy: keep behaviour, not code size. The app is reflection-heavy (Gson, Room,
# Koin) and the savings from aggressive shrinking are small next to the risk of a
# runtime-only crash that unit tests cannot see.
#

# ---------------------------------------------------------------------------
# Kotlin / Java metadata that Gson, Room, Koin and the framework read at runtime
# ---------------------------------------------------------------------------
-keepattributes Signature
-keepattributes *Annotation*
-keepattributes InnerClasses
-keepattributes EnclosingMethod
-keepattributes RuntimeVisibleAnnotations
-keepattributes RuntimeVisibleParameterAnnotations
-keepattributes AnnotationDefault

# ---------------------------------------------------------------------------
# Gson
#
# Gson reflects over field names, so renaming or stripping fields silently changes
# what is (de)serialised. The classes below are passed to Gson().fromJson(...)
# directly or via database.Converters' generic list adapters.
# ---------------------------------------------------------------------------
-keepclassmembers class com.celzero.bravedns.database.** { <fields>; }
-keepclassmembers class com.celzero.bravedns.ui.bottomsheet.** { <fields>; }

-keep class com.google.gson.reflect.TypeToken { *; }
-keep class * extends com.google.gson.reflect.TypeToken
-keepclassmembers,allowobfuscation class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# Gson itself must not be stripped or renamed.
-keep class com.google.gson.** { *; }
-dontwarn com.google.gson.**

# ---------------------------------------------------------------------------
# Kotlin coroutines (debug metadata is read by the debugger only)
# ---------------------------------------------------------------------------
-dontwarn kotlinx.coroutines.**
-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}

# ---------------------------------------------------------------------------
# Enums: Gson and the framework both reach values()/valueOf() reflectively
# ---------------------------------------------------------------------------
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
    **[] $VALUES;
}

# ---------------------------------------------------------------------------
# Kotlin reflection (Koin modules and a few `::class` lookups)
# ---------------------------------------------------------------------------
-keep class kotlin.reflect.** { *; }
-dontwarn kotlin.reflect.**
-keep class kotlin.Metadata { *; }

# ---------------------------------------------------------------------------
# Android framework components declared in the manifest or resolved by name.
# AGP already emits keeps for manifest entries; these cover the rest.
# ---------------------------------------------------------------------------
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider
-keep public class * extends android.app.backup.BackupAgentHelper
-keep public class * extends android.preference.Preference
-keep public class * extends android.view.View
-keep public class com.android.vending.licensing.ILicensingService

# ViewBinding / generated classes
-keep class * implements androidx.viewbinding.ViewBinding { *; }

# ---------------------------------------------------------------------------
# Parcelable / Serializable
# ---------------------------------------------------------------------------
-keepclassmembers class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator CREATOR;
}
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# ---------------------------------------------------------------------------
# JNI / native bridges
#
# firestack ships its own consumer rules; these are the app's own entry points.
# ---------------------------------------------------------------------------
-keepclasseswithmembers,includedescriptorclasses class * {
    native <methods>;
}
-keepclasseswithmembers class * {
    public <init>(android.content.Context, android.util.AttributeSet);
}
-keepclasseswithmembers class * {
    public <init>(android.content.Context, android.util.AttributeSet, int);
}

# ---------------------------------------------------------------------------
# Library warnings that are known-safe
# ---------------------------------------------------------------------------
-dontwarn org.slf4j.**
-dontwarn org.apache.**
-dontwarn java.awt.**
-dontwarn javax.**
-dontwarn org.conscrypt.**
-dontwarn org.bouncycastle.**
-dontwarn org.openjsse.**
-dontwarn android.webkit.**
-dontwarn com.google.errorprone.**
