FROM python:3.8

# install system dependencies
RUN apt-get update && apt-get install -y iptables

# install poetry
RUN pip install "poetry==1.1.11"

# install only library dependencies and leverage docker build cache
WORKDIR /usr/src/app
COPY poetry.lock pyproject.toml ./

RUN poetry config virtualenvs.create false \
    && poetry install --no-dev

# install the project
COPY . .
RUN poetry install --no-dev

CMD ["protect"]
