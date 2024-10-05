FROM gradle:8.10.1-jdk21 AS builder

WORKDIR /home/gradle/src

COPY --chown=gradle:gradle src /home/gradle/src

RUN gradle installDist


FROM openjdk:21

RUN microdnf install findutils

COPY --from=builder /home/gradle/src/app/build/install/app /tmp/app

WORKDIR /tmp/app

CMD ["./bin/app"]
