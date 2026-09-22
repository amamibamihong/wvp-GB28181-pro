FROM eclipse-temurin:21-jre

WORKDIR /opt/wvp

COPY wvp.jar /opt/wvp/wvp.jar

EXPOSE 18978/tcp
EXPOSE 5060/tcp
EXPOSE 5060/udp

ENTRYPOINT ["java", "-Xms512m", "-Xmx1024m", "-XX:+HeapDumpOnOutOfMemoryError", "-XX:HeapDumpPath=/opt/wvp/logs/", "-jar", "/opt/wvp/wvp.jar", "--spring.config.location=/config/application.yml"]
