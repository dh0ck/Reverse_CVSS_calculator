# Reverse CVSS calculator
# Created by dh0ck

import sys

'''
 
CVSS Temporal Equation
 
TemporalScore = BaseScore 
              * Exploitability 
              * RemediationLevel 
              * ReportConfidence
 
Exploitability   = case Exploitability of
                        unproven:             0.85
                        proof-of-concept:     0.9
                        functional:           0.95
                        high:                 1.00
                        not defined           1.00
                        
RemediationLevel = case RemediationLevel of
                        official-fix:         0.87
                        temporary-fix:        0.90
                        workaround:           0.95
                        unavailable:          1.00
                        not defined           1.00
 
ReportConfidence = case ReportConfidence of
                        unconfirmed:          0.90
                        uncorroborated:       0.95      
                        confirmed:            1.00
                        not defined           1.00
 
CVSS Environmental Equation
 
EnvironmentalScore = (AdjustedTemporal 
                        + (10 - AdjustedTemporal) 
                        * CollateralDamagePotential) 
                     * TargetDistribution
 
AdjustedTemporal = TemporalScore recomputed with the Impact sub-equation 
                   replaced with the following AdjustedImpact equation.
 
AdjustedImpact = Min(10, 
                     10.41 * (1 - 
                                (1 - ConfImpact * ConfReq) 
                              * (1 - IntegImpact * IntegReq) 
                              * (1 - AvailImpact * AvailReq)))
 
CollateralDamagePotential = case CollateralDamagePotential of
                                 none:            0
                                 low:             0.1
                                 low-medium:      0.3   
                                 medium-high:     0.4
                                 high:            0.5      
                                 not defined:     0
                                 
TargetDistribution        = case TargetDistribution of
                                 none:            0
                                 low:             0.25
                                 medium:          0.75
                                 high:            1.00
                                 not defined:     1.00
 
ConfReq       = case ConfidentialityImpact of
                        Low:              0.5
                        Medium:           1
                        High:             1.51
                        Not defined       1
 
IntegReq      = case IntegrityImpact of
                        Low:              0.5
                        Medium:           1
                        High:             1.51
                        Not defined       1
 
AvailReq      = case AvailabilityImpact of
                        Low:              0.5
                        Medium:           1
                        High:             1.51
                        Not defined       1
NVD CVSS Overall Score Decision Tree
The CVSS Overall Score is part of the NVD and is not part of the CVSS standard.

    (Calculate OverallScore)
                |
                |
                \/
	<BaseScore Defined?> ----No----> [OverallScore = "Not Defined"] -------------
                |                                                                   |
                |                                                                   |
               Yes                                                                  |
                |                                                                   |
                |                                                                   |
                \/                                                                  |
    [OverallScore = BaseScore]                                                      |
                |                                                                   |
                |                                                                   |
                \/                                                                  |
     <EnvironmentalScore Defined?> --Yes--> [OverallScore = EnvironmentalScore] ----|
                |                                                                   |
                |                                                                   |
                No                                                                  |
                |                                                                   |
                |                                                                   |
                \/                                                                  |
        <TemporalScore Defined?> ---Yes---> [OverallScore = TemporalScore] ---------|
                |                                                                   |
                |                                                                   |
                No                                                                  |
                |                                                                   |
                |                                                                   |
                \/                                                                  |
       (Return OverallScore) <-------------------------------------------------------'''





def calculator(Impact, AC, Auth, AV, conf, intImpact, avImpact):
    if Impact:
        f_impact = 0
    else:
        f_impact = 1.176
    
    if AC == "AC_high":
        AccessComplexity = 0.35
    elif AC == "AC_medium":
        AccessComplexity = 0.61
    elif AC == "AC_low":
        AccessComplexity = 0.71

    if Auth == "Auth_no":
        Authentication = 0.704
    elif Auth == "Auth_single":
        Authentication = 0.56
    elif Auth == "Auth_multiple":
        Authentication = 0.45

    if AV == "AV_local":
        AccessVector = 0.395
    elif AV == "AV_localNetwork":
        AccessVector = 0.646
    elif AV == "AV_network":
        AccessVector = 1 

    if conf == "conf_none":
        ConfImpact = 0
    elif conf == "conf_partial":
        ConfImpact = 0.275
    elif conf == "conf_complete":
        ConfImpact = 0.660

    if intImpact == "intImpact_none":
        IntegImpact = 0
    elif intImpact == "intImpact_partial":
        IntegImpact = 0.275
    elif intImpact == "intImpact_complete":
        IntegImpact = 0.660
    
    if avImpact == "avImpact_none":
        AvailImpact = 0
    elif avImpact == "avImpact_partial":
        AvailImpact = 0.275
    elif avImpact == "avImpact_complete":
        AvailImpact = 0.660
    
    Exploitability = 20 * AccessComplexity * Authentication * AccessVector
    Impact = 10.41 * (1 - (1 - ConfImpact) * (1 - IntegImpact) * (1 - AvailImpact))
    BaseScore = (.6*Impact +.4*Exploitability-1.5)*f_impact
    return BaseScore

Impact_vals = [True, False]
AC_vals = [("AC_high","H"),("AC_medium","M"),("AC_low","L")]
Auth_vals = [("Auth_multiple","M"), ("Auth_single","S"), ("Auth_no","N")]
AV_vals = [("AV_local","L"), ("AV_localNetwork","A"), ("AV_network","N")]
conf_vals = [("conf_none","N"), ("conf_partial","P"), ("conf_complete","C")]
int_impact_vals = [("intImpact_none","N"), ("intImpact_partial","P"), ("intImpact_complete","C")] 
av_impact_vals = [("avImpact_none","N"), ("avImpact_partial","P"), ("avImpact_complete","C")]



initials = {"AV_low"}


cvss_list = []
k = 0
#for a1 in Impact_vals:
a1 = 0
for (a2,a2_vec) in AC_vals:
    for (a3,a3_vec) in Auth_vals:
        for (a4,a4_vec) in AV_vals:
            for (a5,a5_vec) in conf_vals:
                for (a6,a6_vec) in int_impact_vals:
                    for (a7,a7_vec) in av_impact_vals:
                        k += 1
                        cvss = calculator(a1,a2,a3,a4,a5,a6,a7)
                        cvss = round(cvss, 1)
                        
                        cvss_vector = f"(AV:{a4_vec}/AC:{a2_vec}/Au:{a3_vec}/C:{a5_vec}/I:{a6_vec}/A:{a7_vec})"
                        
                        entry = [k,cvss,a2,a3,a4,a5,a6,a7,cvss_vector ]
                        cvss_list.append(entry)
a1 = 1 # Impact_vals
a2 = 0 # AC_vals
a3 = 2 # Auth_vals
a4 = 1 # AV_vals
a5 = 0 # conf_vals
a6 = 2 # int_impact_vals
a7 = 0 # av_impact_vals

for arg in sys.argv:
    if '-h' in arg or 'help' in arg:
        print('\n\n----------- CVSS reverse calculator ----------\n')
        print('Enter target CVSS to obtain possible vectors that produce it.')
        print('An optional second argument specifies the number or desired results.')
        print('Example: python3 reverse_cvss.py 4.3 15\n')
        print('This example prints 15 CVSS vectors that yield a result of 4.3 or similar\n')
        print('Running the script without arguments asks interactively for a CVSS\n')
        print('\n----------------------------------------------\n')
        sys.exit()

if len(sys.argv) == 1:
    target = float(input("Enter target CVSS\n"))
else:
    target = float(sys.argv[1])

#target = 8.2
orders = []
i=0
for cvss_entry in cvss_list:
    orders.append((cvss_entry[0],abs(cvss_entry[1]-target)))

orders.sort(key=lambda y: y[1])

print('='*30)
u=0
if len(sys.argv) > 2:
    results_number = int(sys.argv[2])
else:
    results_number = int(input("Number of results (leave empty for 20 results)") or "20")


for (index,diff) in orders[0:results_number]:
    e = cvss_list[index-1]
    print(e[1],e[-1])

