# Use Ubuntu as the base image
FROM ubuntu:20.04

# Install Python and required libraries
RUN apt-get update && \
    apt-get install -y python3 python3-pip libpcap0.8 libpcap-dev


RUN pip3 install twisted==21.7.0 && \
    pip3 install scapy==2.4.5

# Copy the Python code from the host into the container
COPY ftp.py /app/

# Set the working directory inside the container
WORKDIR /app

# Set the entry point to run the Python code
ENTRYPOINT ["python3", "ftp.py"]