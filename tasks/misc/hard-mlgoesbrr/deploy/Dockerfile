FROM golang:1.22 AS builder

WORKDIR /build

COPY runner/ .

RUN go build -o /build/runner .

FROM rust:1.81.0

WORKDIR /app

COPY --from=builder /build/runner /runner

COPY example_diabetes_model example_diabetes_model

COPY ydfcode ydfcode 
COPY entrypoint.sh entrypoint.sh

WORKDIR /app/ydfcode

RUN ["cargo", "build", "--release", "--all"]

RUN chmod +x /app/entrypoint.sh

CMD ["/app/entrypoint.sh"]



