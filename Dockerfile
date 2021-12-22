FROM python:3.8

WORKDIR /usr/src/app

COPY app/requirements.txt ./
RUN python -m pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt
RUN apt update && apt install -y cmake libdbus-1-dev libdbus-glib-1-dev libcurl4-openssl-dev \
libgcrypt20-dev libselinux1-dev libxslt1-dev libgconf2-dev libacl1-dev libblkid-dev \
libcap-dev libxml2-dev libldap2-dev libpcre3-dev python-dev swig libxml-parser-perl \
libxml-xpath-perl libperl-dev libbz2-dev librpm-dev g++ libapt-pkg-dev libyaml-dev \
libxmlsec1-dev libxmlsec1-openssl
RUN apt install git
RUN git clone https://github.com/gkmadushan/openscap-cis.git
RUN pwd
RUN cd openscap-cis && git checkout fix/1.3.4 && git pull && cd build && cmake ../ && make && make install

COPY . .

CMD [ "uvicorn", "main:app", "--reload", "--host", "0.0.0.0" ]