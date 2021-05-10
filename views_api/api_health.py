#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# imports
from flask_restful import Resource

class Health(Resource):
    def get(self):
        return {'status': 'OK'}