from enum import Enum
from datetime import datetime
from pydantic import Field,model_validator
from .common import StrictModel
class CandidateState(str,Enum): OBSERVATION='OBSERVATION';ANOMALY='ANOMALY';BUG='BUG';LOGIC_BUG='LOGIC_BUG';CRASH='CRASH';PRIMITIVE='PRIMITIVE';EXPLOIT_CANDIDATE='EXPLOIT_CANDIDATE';EXPLOITABLE='EXPLOITABLE';CHAINABLE='CHAINABLE';CLOSED='CLOSED';PARKED='PARKED'
class CandidateSource(str,Enum): FUZZING='fuzzing';DIFFING='diffing';MANUAL='manual';PATCH_DIFF='patch_diff';ORBISPROBE='orbisprobe';TRIAGE='triage'
class Transition(StrictModel):state:CandidateState;at:datetime;actor:str
class CandidateRecord(StrictModel):
    id:str;surface_id:str;source:CandidateSource;state:CandidateState;history:list[Transition]=Field(min_length=1)
    @model_validator(mode='after')
    def _v(self):
        if self.history[-1].state is not self.state:raise ValueError('history state mismatch')
        return self
