Hyperledger Sawtooth CXX SDK Developer's Setup Guide
=============

If you are planning to contribute code to the Sawtooth project, please review
the contributing guide: [CONTRIBUTING.md]

Supported operating systems: Ubuntu 16.04 and macOS

If you want to use a Windows system, we recommend that you install Ubuntu 16.04
in a virtual machine manager, such as Hyper-V or VirtualBox, and develop from
the guest operating system.

**Note:** All commands in this guide use the Bash shell. While the Bash shell
is not strictly required as the command shell, many of the scripts in the build
system are Bash scripts and require Bash to execute.

Step One: Install Docker
-------------
The Sawtooth CXX SDK requirements are:
- Docker Community Edition (version 17.05.0-ce or newer)
- Docker Compose (version 1.13.0 or newer)

Install the Docker software.

macOS:

- Install the latest version of Docker Engine for macOS:
  <https://docs.docker.com/docker-for-mac/install/>

- On macOS, Docker Compose is installed automatically when you install Docker Engine.

Ubuntu:

- Install the latest version of Docker Engine for Linux: <https://docs.docker.com/engine/installation/linux/ubuntu>

- Install Docker Compose: <https://docs.docker.com/compose/install/>

**Note:** The minimum version of Docker Engine necessary is 17.03.0-ce.
  Linux distributions often ship with older versions of Docker.

Next, add your username to the group `docker` to avoid having to run every
docker command as a `sudo`. (Otherwise, you will need to prefix each
command in Step Four, Step Five, and Step Six with `sudo`.)
Run the following command:

```bash
$ sudo adduser $USER docker
```

**Note:** If $USER is not set in the environment on your system, replace $USER in the previous command with your username.

You will need to log out and log back in to your system for the change in group membership to take effect.

Step Two: Configure Proxy (Optional)
-------------

If you are behind a network proxy, follow these steps before continuing.

**Important:** The URLs and port numbers shown below are examples only.
Use the actual URLs and port numbers for your environment.
Contact your network administrator for this information if necessary.

Run the following commands to set the environment variables `http_proxy`, `https_proxy`, and `no_proxy`.

**Important:** Replace the example URLs and ports with the actual URLs and port numbers for your environment.

```bash
  $ export http_proxy=http://proxy-server.example:3128
  $ export https_proxy=http://proxy-server.example:3129
  $ export no_proxy=example.com,another-example.com,127.0.0.0
```

**Note:** Add these commands to either your `.profile` or `.bashrc` file
so you don't have to set them every time you open a new shell.

**Docker Proxy Settings (Optional)**

To configure Docker to work with an HTTP or HTTPS proxy server, follow the
instructions for your operating system:

* macOS - See the instructions for proxy configuration in
  "Get started with Docker for Mac": <https://docs.docker.com/docker-for-mac/>

* Ubuntu - See the instructions for HTTP/HTTPS proxy configuration in
  "Control and configure Docker with systemd": <https://docs.docker.com/engine/admin/systemd/#httphttps-proxy>

Create the file `/etc/systemd/system/docker.service.d/http-proxy.conf` with the
following contents:

**Important:** Replace the example URLs and ports with the actual URLs and port numbers for your environment.

```text
[Service]
Environment="HTTP_PROXY=http://proxy-server.example:3128" "HTTPS_PROXY=http://proxy-server.example:3129" "http_proxy=http://proxy-server.example:3128" "https_proxy=http://proxy-server.example:3129" "no_proxy=example.com,another-example.com,127.0.0.0"
```

**Restart Docker**

```bash
$ sudo systemctl daemon-reload
$ sudo systemctl restart docker
```

Verify that the configuration has been loaded:

```bash
$ systemctl show --property=Environment docker
Environment=HTTP_PROXY=http://proxy-server.example:80/
```

**Docker DNS (Optional)**

Docker build uses `/etc/resolv.conf` for setting up DNS servers for docker image
builds. If you receive `Host not found` errors during docker build steps,
you need to add nameserver entries to the `resolve.conf` file.

**Note:** (Ubuntu only)
Because `resolv.conf` is automatically generated on Ubuntu, you must
install a configuration utility with this command:

```bash
  $ sudo apt-get install resolvconf
```

Edit `/etc/resolvconf/resolv.conf.d/base` as root and add the DNS servers
for your network.

**Note:** If you are behind a firewall, you might need to use specific servers
for your network.

For example, to use Google's public DNS servers:

```
    nameserver 8.8.8.8
    nameserver 8.8.4.4
```

Step Three: Clone the Repository
-------------

**Note:** You must have `git` installed in order to clone the Sawtooth source
code repository. You can find up-to-date installation instructions
at "Getting Started - Installing Git": <https://git-scm.com/book/en/v2/Getting-Started-Installing-Git>.

Open a terminal and run the following commands:

```bash
   $ cd $HOME
   $ mkdir sawtooth
   $ cd sawtooth
   $ git clone https://github.com/hyperledger/sawtooth-sdk-cxx.git
```

Step Four: Build Docker Images
-------------

Two Dockerfiles are included in the repo to help make building and packaging
simpler:

`Dockerfile` is intended to aid local development by providing an environment
suitable for compiling the SDK so dependencies don't need to be installed
locally.

To build the image:

  ```bash
    $ cd sawtooth-sdk-cxx
    $ docker build . -t sawtooth-sdk-cxx-local
  ```

To run the image and compile your local repository:

  ```bash
    $ cd sawtooth-sdk-cxx
    $ docker run -v $(pwd):/project/sawtooth-sdk-cxx sawtooth-sdk-cxx-local
  ```

`Dockerfile-installed` can be used to generate a .deb package from your local
source code as well as a Docker image with the SDK installed from this package.

To build the image:

  ```bash
    $ cd sawtooth-sdk-cxx
    $ docker build -f Dockerfile-installed -t sawtooth-sdk-cxx .
  ```

The .deb artifact will be built and copied into the docker image as part of the
build process. If you'd like to copy it out, you can run the following:

  ```bash
    $ docker run -v $(pwd):/build/debs sawtooth-sdk-cxx bash -c "cp /tmp/*.deb /build/debs"
  ```

You can find the .deb package in the root of `sawtooth-sdk-cxx`.

License
-------

Hyperledger Sawtooth software is licensed under the [Apache License Version 2.0](LICENSE) software license.
