# Docker image for springboot file run
# VERSION 0.0.1
# Author: cdchenw
# Base mirror using java
FROM java:8
# Author
LABEL maintainer="vg <10594559@qq.com>"
# VOLUME using temporary folder /tmp。
# rathing than creating and temporary folder /var/lib/docker in host， and link to container's /tmp folder.
VOLUME /tmp 
# copy jar to docker container and rename to app.jar
ADD smc-gateway-5.0.0.jar app.jar 
# run jar
RUN sh -c 'touch /app.jar'
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]