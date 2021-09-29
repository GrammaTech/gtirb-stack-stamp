FROM ubuntu:18.04

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

# Setup formatting
RUN apt-get update -y && apt-get install -y clang-format curl elpa-paredit \
        emacs-nox git sbcl slime python3-pip python3-protobuf
RUN pip3 install "virtualenv<20.0.0"
RUN pip3 install pre-commit
# Install the lisp-format pre-commit format checker.
RUN curl https://raw.githubusercontent.com/eschulte/lisp-format/master/lisp-format > /usr/bin/lisp-format
RUN chmod +x /usr/bin/lisp-format
RUN echo "(add-to-list 'load-path \"/usr/share/emacs/site-lisp/\")" > /root/.lisp-formatrc

COPY ./.pre-commit-config.yaml /gt/gtirb-stack-stamp/.pre-commit-config.yaml
WORKDIR /gt/gtirb-stack-stamp
RUN git init
RUN pre-commit install-hooks
WORKDIR /
RUN rm -rf /gt/

# Setup build
RUN apt-get install -y build-essential cmake \
        libprotobuf-dev make pkg-config \
        software-properties-common unzip wget
RUN python3 -m pip install --upgrade setuptools wheel

# Setup apt repositories
RUN add-apt-repository ppa:mhier/libboost-latest
RUN wget -O - https://download.grammatech.com/gtirb/files/apt-repo/conf/apt.gpg.key | apt-key add -
# We have to use the stable repository because pypi can only contain stable
# releases of gtirb.
RUN echo "deb https://download.grammatech.com/gtirb/files/apt-repo bionic stable" | tee -a /etc/apt/sources.list
RUN apt-get update -y

# Install Keystone
RUN git clone https://github.com/keystone-engine/keystone.git
RUN cd keystone && \
    mkdir build && \
    cd build && \
    ../make-share.sh && \
    make install && \
    cd .. && \
    rm -rf keystone

RUN ldconfig /usr/local/lib

# Install Python packages
RUN python3 -m pip install --upgrade pip

# Common Lisp Setup
RUN apt-get install -y sbcl
RUN curl -O https://beta.quicklisp.org/quicklisp.lisp
RUN sbcl --load quicklisp.lisp \
        --eval '(quicklisp-quickstart:install)' \
        --eval '(let ((ql-util::*do-not-prompt* t)) (ql:add-to-init-file))'
RUN mkdir -p $HOME/quicklisp/local-projects
WORKDIR /root/quicklisp/local-projects
RUN git clone https://github.com/GrammaTech/cl-utils.git gt/
RUN git clone https://github.com/rpav/cl-interval.git
RUN git clone https://github.com/GrammaTech/cl-capstone.git
RUN git clone --branch quicklisp https://git.grammatech.com/rewriting/gtirb.git
RUN git clone https://github.com/GrammaTech/gtirb-functions.git
RUN git clone https://git.grammatech.com/rewriting/gtirb-capstone.git
RUN git clone https://github.com/GrammaTech/keystone.git
RUN sbcl --eval '(ql:register-local-projects)'
RUN sbcl --eval '(ql:quickload :gtirb-capstone)'
RUN sbcl --eval '(ql:quickload :gt/full)'
