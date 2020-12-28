FROM owasp/modsecurity:3

ENV LDFLAGS="/usr/local/modsecurity/lib/"
ENV CPPFLAGS="/usr/local/modsecurity/include/"
ENV LD_LIBRARY_PATH="/usr/local/modsecurity/lib/:${LD_LIBRARY_PATH}"

# Get pymodsecurity working
RUN apt-get -y update && apt-get -y install python3-pip git
RUN git clone https://github.com/pymodsecurity/pymodsecurity
RUN export LDFLAGS=-L/usr/local/modsecurity/lib/ && export CPPFLAGS=-I/usr/local/modsecurity/include/ && cd pymodsecurity && pip3 install .
RUN LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/modsecurity/lib/

# Pull in CRS
RUN git clone https://github.com/coreruleset/coreruleset /coreruleset
RUN mv /coreruleset/crs-setup.conf.example /coreruleset/crs-setup.conf

# get our application contents
COPY requirements.txt /
RUN pip3 install -r requirements.txt
COPY run_server.py /
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh

CMD ["./entrypoint.sh"]
