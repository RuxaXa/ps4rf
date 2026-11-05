from enum import Enum
from .common import StrictModel
class SurfaceDomain(str,Enum):KERNEL='kernel';BROWSER='browser';MEDIA='media';NETWORK='network';USB='usb';BT='bt';FS='fs';IPC='ipc';GPU='gpu';PUP='pup';SECURE_SERVICE='secure_service';PACKAGE='package';SAVEGAME='savegame'
class Reachability(str,Enum):PROVEN='PROVEN';PARTIAL='PARTIAL';UNPROVEN='UNPROVEN';NOT_REACHABLE='NOT_REACHABLE'
class AttackerControl(str,Enum):NONE='NONE';PARTIAL='PARTIAL';FULL='FULL'
class SurfaceRecord(StrictModel):id:str;domain:SurfaceDomain;entrypoint:str;input:str;privilege:str;reachable:Reachability;attacker_controlled:AttackerControl
