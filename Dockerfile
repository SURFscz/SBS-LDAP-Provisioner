FROM ubuntu:latest

MAINTAINER harry.kodden@surfnet.nl

RUN apt-get update

RUN apt-get -y install git
RUN apt-get -y install wget
RUN apt-get -y install build-essential
RUN apt-get -y install python3.6 python3.6-distutils python3.6-dev
RUN apt-get -y install supervisor && \
    rm -rf /var/lib/apt/lists/* && \
    sed -i 's/^\(\[supervisord\]\)$/\1\nnodaemon=true/' /etc/supervisor/supervisord.conf

RUN apt-get update

ENV DEBIAN_FRONTEND noninteractive    
RUN apt-get -y install libldap2-dev libsasl2-dev slapd ldap-utils python-tox lcov valgrind

VOLUME ["/etc/supervisor/conf.d"]

RUN wget https://bootstrap.pypa.io/get-pip.py

RUN python3.6 get-pip.py

RUN rm get-pip.py

RUN cd /usr/local/bin \
  && rm -f easy_install \
  && rm -f pip \
  && rm -f pydoc \
  && rm -f python

RUN cd /usr/local/bin \
  && ln -s easy_install-3.6 easy_install \
  && ln -s pip3.6 pip \
  && ln -s /usr/bin/pydoc3.6 pydoc \
  && ln -s /usr/bin/python3.6 python

RUN apt-get autoremove
RUN apt-get autoclean

ADD requirements.txt /tmp
RUN pip install --no-cache-dir -r /tmp/requirements.txt

RUN echo 'alias python=python3.6' >> ~/.bashrc

CMD ["supervisord", "-c", "/etc/supervisor/supervisord.conf"]
