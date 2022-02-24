keytool -genkey -alias brahim -keyalg RSA -keystore brahim.jks -keysize 2048
keytool -export -alias brahim  -keystore brahim.jks -rfc -file myCertificate.cert
