# threatmodel-repo
A repository for Threat Models that enables the storage of threat models and correlation of threats across them. 

The goal of a threat model is to capture and communicate the risk of design decisions, software purchases or architectural changes before they're made
so that leadership can make Threat Informed Decisions.

The goals of this tool are to: 
1. Put all our threat models in one place, 2. 
2. Be able aggregate all of the threat data we have into a compelling narrative that can be shared by sub-Line of Business, Line of Business or across the firm as a hole.
3. Be able to identify and communicate trends in our risk decisions over time

# Key features
1. The repository stores our threat models in one place, categorized by Line of Business, overall risk (very high/high/medium/low).
2. The repository enables us to run CISO-level reports that show us aggregate risk, based on MITRE ATT&CK or MITRE ATLAS (for AI threat models).
3. The repository enables us to create threat models that have multiple findings, each finding aligned to either MITRE ATT&CK or MITRE ATLAS.
4. The repository enables us to store one or many diagrams for a single threat model.

# Threat Model Requirements
1. A threat model will have multiple findings, and each finding will have the following entries:
    a. A Threat ID
    b. A Threat Scenario
    c. A Threat Object
    d.  A MITRE ATT&CK or ATLS Technique
    e. A Threat Catalog Rating 
    f. A STRIDE threat category
    g. An inherent risk
    h. A residual risk (which should be blank when a threat model is first built and published, but can be updated later)
    i. A set of mitigation recommendations, either in blob text or stored as a numeric or bulleted list
    j. An owner

2. For each finding, a threat model will have one or many pieces of evidence that prove the threat is mitigated. That evidence must be stored in inexpensive storage.

# Executive Reporting Requirements
1. The first executive report will be to show aggregate risk by sub-Line of Business, Line of Business, and across the estate. 