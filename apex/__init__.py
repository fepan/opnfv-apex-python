##############################################################################
# Copyright (c) 2016 Feng Pan (fpan@redhat.com) and others.
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
##############################################################################


from .net_env import NetworkSettings
from .net_env import ADMIN_NETWORK, PUBLIC_NETWORK, STORAGE_NETWORK, API_NETWORK, PRIVATE_NETWORK, OPNFV_NETWORK_TYPES
import logging

logger = logging.getLogger('apex')
fh = logging.FileHandler('/var/log/apex/apex.log')
fh.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)

logger.addHandler(fh)
logger.addHandler(ch)
