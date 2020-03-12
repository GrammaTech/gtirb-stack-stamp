FROM docker.grammatech.com/rewriting/ddisasm/ubuntu18-gcc

RUN pip3 install keystone-engine capstone

RUN git clone https://github.com/keystone-engine/keystone.git && \
    cd keystone && \
    mkdir build && \
    cd build && \
    ../make-share.sh && \
    make install

