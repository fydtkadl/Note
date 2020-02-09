# **PWNTOOLS**

## **Site**
<https://github.com/Gallopsled/pwntools>

## **Install**

```
apt-get update
apt-get install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential
pip install --upgrade pip
pip install --upgrade pwntools
```

## **Usage**

### GDB

```python
p.process('a.out')
gdb.attach(p,'b*0x08041234\n')
```
