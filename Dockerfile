FROM alpine:3 AS builder
ARG GIT_LOGIN
RUN set -xe \
    && apk add --no-cache --purge -uU git cmake clang20 make openssl-libs-static openssl-dev liburing-dev linux-headers compiler-rt \
	&& rm -rf /var/cache/apk/* /tmp/*
COPY / /src
RUN mkdir /build \
    && CXX=/usr/bin/clang++-20 CC=/usr/bin/clang-20 cmake -S /src -B /build \
            -DASYNCPP_BUILD_TEST=ON -DASYNCPP_WITH_ASAN=ON -DCMAKE_BUILD_TYPE=Release
RUN cmake --build /build -j

FROM alpine:3
RUN set -xe \
    && apk add --no-cache --purge -uU liburing libstdc++ openssl \
	&& rm -rf /var/cache/apk/* /tmp/*
COPY --from=builder /build/asyncpp_io-test /opt/asyncpp_io-test
CMD [ "/opt/asyncpp_io-test" ]