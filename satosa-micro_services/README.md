# CoreAAI Platform plugins for the SATOSA proxy

## Testing

The following text assumes that you have installed and activated `pyenv` on your OS

Install prerequisites:

```
pyenv install 3.5.3
pyenv install 3.7.1
pyenv local 3.5.3 3.7.1
pip install detox
```

Run the tests:

```
tox
```

