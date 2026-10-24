# Strip debug/verbose log calls (they carry connection targets) from
# release builds even where they bypass AppLogger.
-assumenosideeffects class android.util.Log {
    public static *** v(...);
    public static *** d(...);
}

-dontwarn io.netty.**
-keep class io.netty.** { *; }

-keep class com.pishi.ifoxy.vpn.tun.HevSocks5Tunnel { *; }
-keepnames class com.pishi.ifoxy.vpn.tun.HevSocks5Tunnel
-keepclasseswithmembernames class * {
    native <methods>;
}

-keep class org.conscrypt.** { *; }
-dontwarn org.conscrypt.**

-dontwarn io.netty.internal.tcnative.**
-dontwarn io.netty.handler.ssl.OpenSsl**

-keepclasseswithmembers class * {
    kotlinx.serialization.KSerializer serializer(...);
}

-dontwarn com.google.errorprone.annotations.**

-dontwarn reactor.blockhound.**
