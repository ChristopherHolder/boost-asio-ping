FROM debian:9
RUN apt-get update \
    && apt-get install -y python3 \
    && apt-get install -y g++ \
    && apt-get install -y gdb \
    && apt-get install -y libboost-all-dev \
    && apt-get install -y git \
    && apt-get install -y screen
CMD echo "Container ready!"