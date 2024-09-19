FROM ubuntu:20.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    python3-distutils \
    git \
    wget

# Set working directory
WORKDIR /app

# Create a virtual environment and activate it
RUN python3 -m venv venv

# Upgrade pip and install setuptools in the virtual environment
RUN /app/venv/bin/python -m ensurepip --upgrade
RUN /app/venv/bin/pip install setuptools

# Install Unicorn in the virtual environment
RUN /app/venv/bin/pip install unicorn

# Copy necessary files
COPY fw.bin rom.bin sram.bin ./
COPY rehost.py ./

# Run the Python script inside the virtual environment
CMD ["/app/venv/bin/python", "rehost.py"]
