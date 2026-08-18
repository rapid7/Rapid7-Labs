---
title: Shunra Network Virtualization for Hewlett-Packard toServerObject() Remote Code Execution Vulnerability
author: wchen-r7
score: 2
topic_attacker_value: 0
topic_exploitability: 0
topic_disclosure_date: '2014-07-26T15:55:00'
created: '2019-09-12T18:07:29.540852'
revision_date: '2020-10-21T20:25:28.038707'
assessment_id: 8cac3ec4-3e83-4762-aa92-8a11492efc58
topic_id: bbd9ac0e-86ca-429b-b453-0d24b6d0124b
topic_short_id: KL6I4Vu4M7
topic_slug: shunra-network-virtualization-for-hewlett-packard-toserverobject-remote-code-execution-vulnerability
akb_topic_url: https://attackerkb.com/topics/KL6I4Vu4M7/shunra-network-virtualization-for-hewlett-packard-toserverobject-remote-code-execution-vulnerability
akb_assessment_url: https://attackerkb.com/topics/KL6I4Vu4M7/shunra-network-virtualization-for-hewlett-packard-toserverobject-remote-code-execution-vulnerability#8cac3ec4-3e83-4762-aa92-8a11492efc58
---

# Shunra Network Virtualization for Hewlett-Packard toServerObject() Remote Code Execution Vulnerability

*Assessment by wchen-r7, archived from [AttackerKB](https://attackerkb.com/topics/KL6I4Vu4M7/shunra-network-virtualization-for-hewlett-packard-toserverobject-remote-code-execution-vulnerability#8cac3ec4-3e83-4762-aa92-8a11492efc58).*

---

The specific flaw exists within the toServerObject function. The method does not properly sanitize the input to this function allowing for directory traversal. An attacker can leverage this vulnerability to write files under the context of SYSTEM and achieve remote code execution.

* The URL to access the web service:

```
public static final String WS_NETWORKEDITOR_TO_SERVER_OBJECT_URI = "/savefile/{filename}";
```

* The "toServerObject" web service API:

```
public ShunraClientResponse toServerObject(String s, UIObject uiobject)
    throws Exception
{
    try
    {
        return m_controller.toServerObject(uiobject, s);
    }
    catch(Exception exception)
    {
        exception.printStackTrace();
        m_logger.error(exception.getMessage(), exception);
        throw exception;
    }
}
```

Everything is delegated to :

```
private NetworkEditorController m_controller;
```

# The NetworkEditorControllerImpl toServerObject:

```
public ShunraClientResponse toServerObject(UIObject uiobject, String s)
{
    m_logger.debug("toServerObject");
    FlowValidator flowvalidator = new FlowValidator();
    try
    {
        uiobject.fileName = s;
        ShunraClientResponse shunraclientresponse = new ShunraClientResponse();
        ErrorMessages errormessages = new ErrorMessages();
        if(uiobject.flows.size() == 0)
            errormessages.generalErrors.add("Currently there are no flows to download");
        else
            errormessages = flowvalidator.ValidateCollisionsBetweenFlows(uiobject.flows);
        if(errormessages.containsErrors())
        {
            shunraclientresponse.SetFailure(errormessages);
        } else
        {
            ObjectsConverter objectsconverter = new ObjectsConverter();
            FilesConverter filesconverter = new FilesConverter();
            NtxObjectRepresentation ntxobjectrepresentation = objectsconverter.ConvertFromUIObjectToMultiFlowNtx(uiobject);
            String s1 = filesconverter.ConvertFromObjectToFile(ntxobjectrepresentation);
            String s2 = storage.saveTemporaryForDownload(s, s1);
            shunraclientresponse.SetSuccess(s2);
        }
        return shunraclientresponse;
    }
    catch(Exception exception)
    {
        exception.printStackTrace();
    }
    return null;
}
```


Where "s" is the file path and is user controlled. By default files are saved to "c:\\windows\\temp\\files" (win 2003 sp2).

The attacker controles "s" through the URL, with "..\\" sequences is posible to directory traversa.

Unfortunately contents (s1) are JSON converted contents. Example valid JSON:

```
{
    "fileName": "ntxFile",
    "flows": [{
        "wanCloud": {
            "latency": {
                "latencyType": "Fixed",
                "latency": 75
            },
            "packetLoss": {
                "packetLossType": "None"
            },
            "bitError": {
                "isActive": false,
                "avgFrequency": 0,
                "min": 0,
                "max": 0
            },
            "congestion": {
                "isActive": false,
                "avgFrequency": 0,
                "min": 0,
                "max": 0,
                "fixedLatency": {
                    "latencyType": "Fixed",
                    "latency": 0
                },
                "randomPacketLoss": {
                    "packetLossType": "Random",
                    "chance": 0
                }
            },
            "disconnect": {
                "isActive": false,
                "avgFrequency": 0,
                "min": 0,
                "max": 0
            },
            "duplicatePackets": {
                "isActive": false,
                "chance": 0,
                "min": 0,
                "max": 0
            },
            "fragmentation": {
                "isActive": false,
                "chance": 0,
                "maxTransmitUnit": 0,
                "behavior": "Ignore"
            },
            "outOfOrder": {
                "isActive": false,
                "chance": 0,
                "min": 0,
                "max": 0
            }
        },
        "clientGateway": {
            "bandwidth": {
                "upLink": {
                    "isManual": true,
                    "bandwidth": 330
                },
                "downLink": {
                    "isManual": true,
                    "bandwidth": 780
                }
            },
            "isActiveBucketLimitation": false,
            "bucketLimitation": null,
            "isActivePacketOverhead": false,
            "packetType": null
        },
        "serverGateway": {
            "bandwidth": {
                "upLink": {
                    "isManual": true,
                    "bandwidth": 0
                },
                "downLink": {
                    "isManual": true,
                    "bandwidth": 0
                }
            },
            "isActiveBucketLimitation": false,
            "bucketLimitation": null,
            "isActivePacketOverhead": false,
            "packetType": null
        },
        "endpoints": {
            "serverEndpoint": {
                "rangeGroups": [{
                    "includeRange": {
                        "fromIp": "1.0.0.0",
                        "toIp": "255.255.255.255",
                        "protocol": "ALL",
                        "port": 0
                    },
                    "excludeRanges": [{
                        "fromIp": "1.0.0.0",
                        "toIp": "1.0.0.0",
                        "protocol": "ALL",
                        "port": 0
                    }]
                }],
                "rangeDefinition": "custom"
            },
            "clientEndpoint": {
                "rangeGroups": [{
                    "includeRange": {
                        "fromIp": "1.0.0.0",
                        "toIp": "1.0.0.0",
                        "protocol": "ALL",
                        "port": 0
                    },
                    "excludeRanges": []
                }],
                "rangeDefinition": "custom"
            }
        },
        "packetList": true,
        "name": "3G"
    }]
}
```


It allows to create a File like;

```
<NETWOR_X ID="Network_Editor" NAME="..\..\..\metasploit2.txt" ORIGIN="Network Editor Multi Flow" CREATED_BY="Network Editor Multi Flow" CREATED_ON_DATE="14-08-27 17:32:41" NETWOR_X_VERSION="2.2" CREATED_ON_HOST_NAME="juan-6ed9db6ca8">
  <NET_OBJECTS>
    <WAN_CLOUD FLOW_ID="FLOWS_1-3G" ID="ID_WAN_CLOUD_FLOWS_1-3G" NAME="Wan" DESCRIPTION="3G">
      <FIXED_LATENCY LATENCY="75.0"/>
    </WAN_CLOUD>
    <GATEWAY FLOW_ID="FLOWS_1-3G" ID="ID_CLIENT_GW_FLOWS_1-3G" NAME="Clientgateway">
      <NICS>
        <NIC FLOW_ID="FLOWS_1-3G" ID="ID_CLIENT_GW__NIC_1_FLOWS_1-3G" NAME="ClientDownlink" BANDWIDTH="780.0" IN_BW_UTIL="0" OUT_BW_UTIL="0" PACKET_OVERHEAD_BYTES=""/>
        <NIC FLOW_ID="FLOWS_1-3G" ID="ID_CLIENT_GW__NIC_2_FLOWS_1-3G" NAME="ClientUplink" BANDWIDTH="330.0" IN_BW_UTIL="0" OUT_BW_UTIL="0" PACKET_OVERHEAD_BYTES=""/>
      </NICS>
    </GATEWAY>
    <GATEWAY FLOW_ID="FLOWS_1-3G" ID="ID_SERVER_GW_FLOWS_1-3G" NAME="Servergateway">
      <NICS>
        <NIC FLOW_ID="FLOWS_1-3G" ID="ID_SERVER_GW__NIC_1_FLOWS_1-3G" NAME="ServerUplink" BANDWIDTH="0.0" IN_BW_UTIL="0" OUT_BW_UTIL="0" PACKET_OVERHEAD_BYTES=""/>
        <NIC FLOW_ID="FLOWS_1-3G" ID="ID_SERVER_GW__NIC_2_FLOWS_1-3G" NAME="ServerDownlink" BANDWIDTH="0.0" IN_BW_UTIL="0" OUT_BW_UTIL="0" PACKET_OVERHEAD_BYTES=""/>
      </NICS>
    </GATEWAY>
    <ENDPOINT FLOW_ID="FLOWS_1-3G" ID="ID_CLIENT_FLOWS_1-3G" NAME="Client">
      <INCLUDE_IPS>
        <IP_RANGE FROM_IP="1.0.0.0" TO_IP="1.0.0.0" PROTOCOL="0" PORT="0" IP_VERSION="4"/>
      </INCLUDE_IPS>
    </ENDPOINT>
    <ENDPOINT FLOW_ID="FLOWS_1-3G" ID="ID_SERVER_FLOWS_1-3G" NAME="Server">
      <INCLUDE_IPS>
        <IP_RANGE FROM_IP="1.0.0.0" TO_IP="255.255.255.255" PROTOCOL="0" PORT="0" IP_VERSION="4"/>
      </INCLUDE_IPS>
      <EXCLUDE_IPS>
        <IP_RANGE FROM_IP="1.0.0.0" TO_IP="1.0.0.0" PROTOCOL="0" PORT="0" IP_VERSION="4"/>
      </EXCLUDE_IPS>
    </ENDPOINT>
    <PACKET_LIST FLOW_ID="FLOWS_1-3G" ID="ID_PACKET_LIST_CLIENT_FLOWS_1-3G" NAME="PACKET_LIST_CLIENT_FLOWS_1-3G"/>
  </NET_OBJECTS>
  <LINKS>
    <LINK TO_OBJECT="ID_PACKET_LIST_CLIENT_FLOWS_1-3G" FROM_OBJECT="ID_CLIENT_FLOWS_1-3G" UNIDIRECTIONAL="false"/>
    <LINK TO_OBJECT="ID_CLIENT_GW__NIC_1_FLOWS_1-3G" FROM_OBJECT="ID_PACKET_LIST_CLIENT_FLOWS_1-3G" UNIDIRECTIONAL="false"/>
    <LINK TO_OBJECT="ID_WAN_CLOUD_FLOWS_1-3G" FROM_OBJECT="ID_CLIENT_GW__NIC_2_FLOWS_1-3G" UNIDIRECTIONAL="false"/>
    <LINK TO_OBJECT="ID_SERVER_GW__NIC_1_FLOWS_1-3G" FROM_OBJECT="ID_WAN_CLOUD_FLOWS_1-3G" UNIDIRECTIONAL="false"/>
    <LINK TO_OBJECT="ID_SERVER_FLOWS_1-3G" FROM_OBJECT="ID_SERVER_GW__NIC_2_FLOWS_1-3G" UNIDIRECTIONAL="false"/>
  </LINKS>
</NETWOR_X>
```


Text contents can be controlled. Feasible attack vector: upload a JSP. Problems

* Shunra doesn't handle JSP directly.
* Use the HP LoadRunner instance, unfortunately it's not necessary to run it to have Shunra running. So it's hard to write a reliable
exploit which work son the default conditions.


Maybe there is something I'm forgetting to get reliable code execution with not full controled (text contents) traversal...feedback is welcome.
