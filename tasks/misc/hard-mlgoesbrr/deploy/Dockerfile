FROM golang:1.22 AS builder

WORKDIR /build

COPY runner/ .

RUN go build -o /build/runner .

FROM rust:1.81.0

WORKDIR /app

COPY --from=builder /build/runner /runner

COPY flag.txt /flag.txt
COPY ydfcode ydfcode 

CMD ["/runner", "-ydf", "/app/ydfcode"]


