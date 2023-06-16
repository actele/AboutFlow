# AppScanner - Automatic Fingerprinting of Smartphone Apps From Encrypted Network Traffic 分析报告
## 一、论文概况

---



### 标题
AppScanner: Automatic Fingerprinting of Smartphone Apps From Encrypted Network Trafﬁc

### 收录会议或期刊
N/A

### 作者
Vincent F. Taylor∗, Riccardo Spolaor†, Mauro Conti† and Ivan Martinovic∗

### 摘要
Abstract—Automatic ﬁngerprinting and identiﬁcation of smartphone apps is becoming a very attractive data gathering technique for adversaries, network administrators, investigators and marketing agencies. In fact, the list of apps installed on a device can be used to identify vulnerable apps for an attacker to exploit, uncover a victim’s use of sensitive apps, assist network planning, and aid marketing。

### 编号
N/A

### 作者邮箱
∗Department of Computer Science, University of Oxford, Oxford, United Kingdom {vincent.taylor, ivan.martinovic}@cs.ox.ac.uk
†Department of Mathematics, University of Padua, Padua, Italy {riccardo.spolaor, conti}@math.unipd.it

### 中文摘要
本文提出了一种自动指纹识别和识别智能手机应用程序的方法。该方法可用于各种领域，如攻击者利用易受攻击的应用程序进行攻击，揭示受害者使用敏感应用程序信息，协助网络规划和市场营销等。

---



## 二、论文翻译



## 

---

 ## 原文[0/16]： 

 

 Vincent F. Taylor∗, Riccardo Spolaor†, Mauro Conti† and Ivan Martinovic∗ 

∗Department of Computer Science University of Oxford, Oxford, United Kingdom {vincent.taylor, ivan.martinovic}@cs.ox.ac.uk †Department of Mathematics University of Padua, Padua, Italy {riccardo.spolaor, conti}@math.unipd.it

 1. Introduction 

Smartphone and mobile device usage continues to grow at a remarkable pace as devices become more powerful, feature-rich and more affordable. Gartner reports that sales of smartphones to consumers exceeded one billion units in 2014 alone, up 28.4% over 2013 [1]. Additionally, they report that two-thirds of mobile handsets sold in the world were smartphones. Flurry, a mobile analytics company, re ports that overall app usage grew by 76% in 2014 [2]. Smartphones are well-equipped out of the box, but users regularly download and install add-on applications, called apps, to introduce additional features and functionality. The intense demand for smartphones, and rapid increase in app usage, makes the mobile platform a prime target for any individual or organisation looking to identify the presence of speciﬁc apps on users’ smartphones, whether for benevolentor malevolent reasons.

 On personal computers, many techniques have been used to identify types of network trafﬁc, as well as the applica tions that generated this trafﬁc. Nguyen and Armitage [3] survey machine learning techniques for Internet trafﬁc clas siﬁcation. Traditionally, TCP/IP trafﬁc may be identiﬁed by port number, since it is common for applications to use “well-known” destination port numbers that are reserved for each type of service. In the case of identifying multiple sources of trafﬁc from services that use the same port num ber (for example web browsing), it can sometimes sufﬁce to rely on the HTTP host header or destination IP address to identify the recipient of the communication. However, in the mobile landscape, trafﬁc ﬁngerprinting is complicated by the fact that many apps communicate exclusively with their servers by sending and receiving data using HTTP/HTTPS. In the case where developers opt to use HTTPS, the payload is encrypted and thus cannot be inspected to help identify the app that the trafﬁc originated from. Additionally, for scalability reasons, many developers and ad networks use content distribution networks (CDNs) to deliver content and provide APIs to their apps. The use of CDNs and APIs means that more than one app may send (and receive) data to (and from) the same IP address or IP address range, thus frustrating app identiﬁcation attempts that rely on IPaddresses.

 Users typically install apps in line with their interests. Thus, merely knowing what apps a user has installed on their device can provide valuable proﬁling information about the user [4]. This proﬁling information is valuable to advertisers, governments, or rogue individuals intent on invading that  

---

 ## 翻译[0/16]：
 

# Vincent F. Taylor∗, Riccardo Spolaor†, Mauro Conti†和Ivan Martinovic∗ 

∗牛津大学计算机科学系，英国牛津，{vincent.taylor，ivan.martinovic}@cs.ox.ac.uk
† 帕多瓦大学数学系，意大利帕多瓦，{riccardo.spolaor，conti}@math.unipd.it

# 1. 引言

随着智能手机和移动设备变得更加强大、功能丰富和更加经济实惠，智能手机和移动设备的使用量正在以惊人的速度增长。《财富》杂志报道，仅在2014年，智能手机销量就超过了10亿台，比2013年增长了28.4% [1]。此外，他们报告称，全球销售的移动终端中有三分之二是智能手机。移动分析公司Flurry表示，2014年应用程序的总使用量增长了76% [2]。智能手机已经配备了许多功能，但用户经常下载和安装不同的应用程序，也被称为应用程序或App，来获得额外的功能和功能。智能手机的强烈需求和快速增长的应用程序使用量，使得移动平台成为任何寻求在用户智能手机上识别特定应用程序存在的个人或组织的主要目标，无论是出于善意还是恶意。

在个人计算机上，已经使用了许多技术来识别网络流量的类型以及产生这种流量的应用程序。Nguyen和Armitage [3]对互联网流量分类的机器学习技术进行了调查。传统上，TCP/IP流量可以通过端口号进行识别，因为应用程序使用“众所周知”的目标端口号，这些端口号都为每个服务保留。例如，要识别使用相同端口号的服务的多个流量源（例如Web浏览），有时可能仅需依赖HTTP主机标头或目标IP地址即可识别通信的接收者。但是，在移动领域，流量指纹识别存在复杂性，因为许多应用程序仅通过使用HTTP/HTTPS发送和接收数据与其服务器通信。在开发人员选择使用HTTPS的情况下，负载是加密的，因此无法检查以确定流量来源应用程序。此外，为了可扩展性的原因，许多开发人员和广告网络使用内容分发网络（CDN）来提供API并传输内容。使用CDN和API意味着多个应用程序可能向（和从）同一IP地址或IP地址范围发送（和接收）数据，从而破坏了基于IP地址的应用程序识别尝试。

用户通常根据自己的兴趣安装应用程序。因此，仅仅知道用户在其设备上安装了哪些应用程序就可以提供有价值的用户档案信息[4]。这些档案信息对于广告商、政府或入侵用户隐私的无赖个人都有价值。

## 

---

 ## 原文[1/16]： 

 
 2016 IEEE European Symposium on Security and Privacy individual’s privacy. On the other hand, the list of apps users have installed on their devices may be very useful to network administrators concerned with network planning, security, or trafﬁc engineering. We consider an actor capable of passively monitoring network trafﬁc or otherwise being able to obtain network traces. We motivate our work by outlining four concrete scenarios where app ﬁngerprinting and identiﬁcation may be useful to such an actor. Attackers targeting speciﬁc apps. An adversary in pos session of exploits (perhaps zero-day exploits) for particular apps may use app ﬁngerprinting to identify vulnerable apps on a network. The adversary can build a ﬁngerprint of a vulnerable app (or vulnerable version of an app) “ofﬂine” and then later use it to identify these apps in the wild. Once vulnerable apps have been identiﬁed, the adversary may then exploit these vulnerabilities for their own beneﬁt. It is particularly worrying to consider an adversary ﬁngerprinting and scanning for vulnerable mobile banking apps on users’ devices. By performing app ﬁngerprinting, the adversary increases their accuracy in targeting victims, and becomes more discreet when attacking by not needing to “broadcast” their attack to users who are not vulnerable. Attackers targeting speciﬁc users. App ﬁngerprinting may also be used in situations where there are speciﬁc targets. By joining a victim’s network (or merely staying within wireless range without associating with the network), an adversary could surreptitiously monitor and ﬁngerprint the victim’s trafﬁc to identify what apps the victim was using or had installed on his/her device. For high-proﬁle clients this may be highly undesirable since merely knowing what apps the victim uses on their smartphone may be quite signiﬁcant. For example, a competitor may think it would be interesting to the general public to know that a married politician was using a dating/ﬂirting app on his/her device. The gravity of this problem is highlighted when one con siders the Advanced Persistent Threat (APT) context where high-proﬁle persons are targeted. Once a list of apps have been identiﬁed, the adversary may then go on to obtaining the relevant exploits to attempt to take control of the victim’s device or data. In this scenario, app ﬁngerprinting is used to reduce the potential cost (in terms of both time and money) for exploiting a victim by quickly and easily enumerating the services that the victim uses. Presumably, the adversary will then use the most cost-effective avenue to attack thevictim.

 Network management. App ﬁngerprinting provides valuable data about the types of apps and usage patterns of these apps within an organisation. In the current era of bring-your-own-device (BYOD), this information would be invaluable to network administrators wanting to optimize their networks. For example, knowing the most popular apps and their throughput and latency requirements for good user experience, administrators could then conﬁgure their network so that particular apps performed more efﬁciently. Additionally, app ﬁngerprinting may be used to determine whether disallowed apps were being used on an enterprise network. The administrator could then take appropriate ac-tion against the offender.

 Advertising and market research. App ﬁngerprinting can be a valuable aid to market research. Suppose an analytics ﬁrm wants to know the popularity of apps in a particular location or during a particular event (e.g. during a football match). This ﬁrm could potentially ﬁngerprint apps and then go into their location of interest to identify app usage from within a crowd of users. By ﬁngerprinting app usage within a target population, advertisers may be better able to build proﬁles of their target market, and consequently target advertisements to users more efﬁciently.

 1.1. Contributions 

In this paper we introduce AppScanner, a framework implementing a robust and extensible methodology for the automatic ﬁngerprinting and real-time identiﬁcation of An droid apps from their network trafﬁc, whether this trafﬁc is encrypted or unencrypted. We have built and tested App Scanner with Android devices and apps. However, due to its modular design, AppScanner can be easily ported to ﬁngerprint and identify apps on other platforms such as iOS/Windows/Blackberry. Our main contributions are the following: • Enumerating strategies for network trafﬁc pre processing that enable accurate extraction of features that can be reliably used to re-identify an app. • Outlining a method of obtaining perfect ground truth of what app is responsible for each network transmissionusing a novel demultiplexing strategy.

 • Providing a highly-scalable supervised learning frame work that can be used to accurately model and lateridentify trafﬁc ﬂows from apps.  

---

 ## 翻译[1/16]：
 

本文介绍了2016年IEEE欧洲安全与隐私研讨会中的一个议题-个人隐私和网络管理之间的平衡。在用户设备上安装的应用程序清单可能对关注网络规划、安全或流量工程的网络管理员非常有用。我们考虑一个能够被动监测网络流量或以其他方式获取网络跟踪的行动者。我们通过描述四种具体情景来激发我们的工作动机，其中应用指纹技术和识别对此类行动者可能非常有用。具体来说：攻击针对特定应用程序。拥有特定应用程序漏洞的攻击者（可能是零日攻击）可以利用应用指纹技术识别网络中易受攻击的应用程序。攻击者可以“离线”建立易受攻击应用程序（或易受攻击版本的应用程序）的指纹，然后在以后利用它来识别这些应用程序。一旦确定易受攻击的应用程序，攻击者可以为了自己的利益利用这些漏洞。对于在用户设备上搜索易受攻击的移动银行应用程序的攻击者，这尤其令人担忧。通过应用指纹技术，攻击者提高了对受害者的精准度，并通过不需要向不易受攻击的用户广播攻击来变得更加隐蔽。攻击特定用户。应用指纹技术还可以在特定目标的情况下使用。通过加入受害者的网络（或仅仅停留在无线范围内而不与网络关联），攻击者可以偷偷地监视和指纹识别受害者的流量，以确定受害者在使用或安装哪些应用程序。对于高调客户来说，仅仅知道受害者在智能手机上使用哪些应用程序可能会是非常重要的。例如，竞争对手可能认为让公众知道一位已婚政治家在其设备上使用约会/调情应用程序是一件有趣的事情。当考虑到高级持续性威胁（APT）环境时，目标是高调人士。一旦确定了应用程序列表，攻击者可以获取相关漏洞利用程序，试图控制受害者的设备或数据。在这种情况下，应用程序指纹技术用于减少攻击受害者的潜在成本（无论是时间还是金钱），通过快速和容易地枚举受害者使用的服务来实现。网络管理。应用指纹技术提供了有关组织中应用类型和使用模式的有价值数据。在自带设备（BYOD）当前的时代，这些信息对于希望优化其网络的网络管理员无价。例如，了解最受欢迎的应用程序及其需要经过的吞吐量和延迟以实现良好的用户体验，管理员可以配置其网络使特定的应用程序更加高效地运行。此外，应用指纹技术可以用于确定是否在企业网络上使用禁止使用的应用程序。管理者可以对违规者采取适当的行动。广告和市场研究。应用指纹技术可以成为市场研究的有价值工具。假设一个分析公司想要知道特定位置或特定事件（例如足球比赛期间）中应用程序的受欢迎程度，该公司可以通过应用指纹技术潜在地指纹识别应用程序，然后在它们感兴趣的位置确定来自用户群体的应用程序使用情况。通过指纹识别目标人群的应用程序使用情况，广告商可以更好地建立他们的目标市场的资料档案，从而更有效地针对用户投放广告。本文介绍了一个名为AppScanner的框架，它实现了一种自动化指纹识别和实时识别Android应用程序的健壮和可扩展的方法，无论该流量是加密还是未加密。我们已经使用Android设备和应用程序构建和测试了AppScanner。由于其模块化的设计，AppScanner可以很容易地用于指纹识别其他平台上的应用程序，如iOS/Windows/Blackberry。我们的主要贡献如下：枚举网络流量预处理策略，使其能够准确提取可靠用于重新识别应用程序的特征。描述一种获得每个网络传输负责的每个应用程序的完美基础真实性的方法，使用一种新颖的复用策略。提供了一个高度可扩展的监督学习框架，可用于准确地建模和后来识别应用程序的流量流。

## 

---

 ## 原文[2/16]： 

 
 • Outlining a method for real-time classiﬁcation of inter cepted Wi-Fi trafﬁc leveraging live packet capture. • Comparing the performance of various classiﬁcation strategies for identifying smartphone apps from encrypted network trafﬁc. The rest of the paper is organised as follows: Section 2 discusses work related to trafﬁc analysis and ﬁngerprinting; Section 3 outlines the design of AppScanner and how the different components work together to ﬁngerprint an app; Section 4 discusses the classiﬁcation strategies that were tested; Section 5 evaluates the performance of AppScanner; Section 6 discusses the limitations of AppScanner and high lights areas of future work; and ﬁnally Section 7 concludesthe paper.

 2. Related Work 

Trafﬁc analysis and ﬁngerprinting is by no means a new area of research, and indeed much work has been done on analysing trafﬁc from workstations and web browsers [5]. At ﬁrst glance, it may seem that trafﬁc analysis and ﬁn gerprinting of smartphone apps is a simple translation of existing work. While there are some similarities, such as end-to-end communication using IP addresses/ports, there are nuances in the type of trafﬁc sent by smartphones and the way in which it is sent that makes trafﬁc analysis in the realm of smartphones distinct from trafﬁc analysis on traditional workstations [6][7][8]. In the remainder of this section, we consider traditional trafﬁc analysis approaches on workstations (Section 2.1), and then we look at trafﬁcanalysis on smartphones (Section 2.2).

 2.1. Traditional Trafﬁc Analysis on Workstations 

Traditional analysis approaches have relied on artefacts of the HTTP protocol to make ﬁngerprinting easier. For ex ample, when requesting a web page, a browser will usually fetch the HTML document and all corresponding resources identiﬁed by the HTML code such as images, JavaScript and style-sheets. This simpliﬁes the task of ﬁngerprinting a web page since the attacker has a corpus of information (IP addresses, sizes of ﬁles, number of ﬁles) about the various resources attached to an individual document. Many app developers, for scalability, build their app APIs on top of content delivery networks (CDNs) such as Akamai or Amazon AWS [9]. This reduces (on average) the space of endpoints that apps communicate with. In the past, it may have been useful to look at the destination IP address of some trafﬁc and infer the app that was sending the trafﬁc. Presently, requests to graph.facebook.com, for example, may possibly be from the Facebook app but they may also be from a wide range of apps that query the Facebook Graph API. With the advent of CDNs and standard web service APIs, more and more apps are sending their trafﬁc to similar endpoints and this frustrates attempts to ﬁngerprint app trafﬁc based on destination IP address only. In the literature, several works considered strong adver saries (e.g., governments) that may leverage trafﬁc analysis. Those adversaries are able to capture the network trafﬁc ﬂowing through communication links [10]. Liberatore et al. [11] showed the effectiveness of proposals aiming to identify web-pages via encrypted HTTP trafﬁc analysis. Subsequently, Herman et al. [12] outperformed Liberatore et al. by presenting a method that relies on common text min ing techniques to the normalized frequency distribution of observable IP packet sizes. This method correctly classiﬁed some 97% of HTTP requests. Similar work was proposed by Panchenko et al. [13]. Their proposal correctly identiﬁed web pages despite the use of onion routing techniques such as Tor. More recently, Cai et al. [14] presented a web page ﬁngerprinting attack and showed its effectiveness despite trafﬁc analysis countermeasures (e.g., HTTPOS). Unfortunately, these pieces of work were not designed for smartphone trafﬁc analysis. Indeed, the authors focus on identifying web pages on a traditional PC and leverage the fact that the HTTP trafﬁc can be very unique depending on how the web page is designed. On smartphones, although apps communicate using HTTP, they do so usually through text-based APIs, removing rich trafﬁc features present intypical HTTP web page trafﬁc.

 2.2. Trafﬁc Analysis on Smartphones   

---

 ## 翻译[2/16]：
 

• 提出一种实时分类拦截的Wi-Fi数据流量的方法，利用实时数据包捕获技术。 
• 比较各种分类策略对于从加密网络数据流量中识别智能手机应用的性能。 
本文的其余部分安排如下：第2节讨论与流量分析和指纹识别相关的研究；第3节概述AppScanner的设计及其不同的组件如何协同工作来识别应用程序的特征；第4节讨论测试过的分类策略；第5节评估AppScanner的性能；第6节讨论AppScanner的局限性，并突出未来的研究领域；最后，第7节总结全文。

# 2. 相关工作 

流量分析和指纹识别并不是一个新领域的研究，研究人员已经对工作站和网络浏览器的流量进行了大量分析研究[5]。乍一看，流量分析和指纹识别智能手机应用似乎是对现有研究的简单翻版。虽然有一些相似之处，比如使用IP地址/端口进行端到端通信，但智能手机发送的流量类型和发送方式上的细微差别使得智能手机的流量分析与传统工作站的流量分析有所不同[6][7][8]。在本节的其余部分，我们将考虑传统工作站上的流量分析方法（第2.1节），然后看看在智能手机上的流量分析方法（第2.2节）。

# 2.1. 传统工作站上的流量分析 

传统的分析方法一直依赖于HTTP协议的参数来简化指纹识别。例如，在请求网页时，浏览器通常会获取HTML文档并获取HTML代码标识的所有相关资源（如图像、JavaScript和样式表）。这简化了对网页进行指纹识别的任务，因为攻击者可以获取有关附属于单个文档的各种资源（IP地址、文件大小、文件数量）的大量信息。为了可扩展性，许多应用开发者会在内容分发网络（CDN）上构建其应用程序接口，例如Akamai或Amazon AWS [9]。这通常会减少应用程序通信的终点空间。过去，查看某些流量的目标IP地址并推断发送该流量的应用程序可能会很有用。例如，对graph.facebook.com的请求可能来自Facebook应用程序，也可能来自查询Facebook Graph API的各种应用程序。随着CDN和标准Web服务API的出现，越来越多的应用程序将它们的流量发送到类似的终点，这使得仅基于目标IP地址指纹识别应用程序流量的企图变得更加困难。在文献中，有几个研究考虑到强大的敌对方（例如政府）可能利用流量分析来攻击。这些敌人能够捕获通过通信链路流动的网络流量[10]。Liberatore等人[11]展示了通过加密的HTTP流量分析识别网页的建议的有效性。随后，Herman等人[12]通过提出一种方法来依赖于常见的文本挖掘技术，来归一化可观察IP数据包大小的频率分布，从而超过了Liberatore等人。该方法正确地分类了97％的HTTP请求。Panchenko等人[13]提出的类似工作，可以正确地识别Web页面，即使使用了类似Tor的洋葱路由技术。最近，Cai等人[14]提出了一种网络页面指纹识别攻击，并展示了其有效性，尽管存在流量分析对策（例如HTTPOS）。不幸的是，这些研究工作并不是为智能手机流量分析而设计的。事实上，这些作者集中于在传统PC上识别Web页面，并利用HTTP流量可以根据网页设计方式的不同而非常独特的事实。在智能手机上，虽然应用程序使用HTTP进行通信，但通常是通过基于文本的API完成的，这消除了典型的HTTP网页流量中存在的丰富流量特征。 

# 2.2。智能手机上的流量分析

## 

---

 ## 原文[3/16]： 

 
A number of authors have proposed different schemes for identifying smartphone apps and smartphones them selves from smartphone trafﬁc. These schemes have relied on inspecting IP addresses and packet payloads among other things. The methodology and framework we propose in this paper uses IP addresses only for ﬂow separation (i.e., not for feature generation, as explained in Section 3) and does not leverage any information contained in packet payloads. Dai et al. [15] propose NetworkProﬁler, an automated approach to proﬁling and identifying Android apps using dynamic methods. They use a user-interface (UI) fuzzing technique to automatically try different execution paths in an app, while the network traces are being monitored. They inspect HTTP payloads and thus this technique suffers from the fact that it only works on unencrypted trafﬁc. Dai et al. did not have the full ground truth of the trafﬁc traces they were analysing, so it is difﬁcult to systematically quantify how accurate NetworkProﬁler was in terms of precision,recall, and overall accuracy.

 In what is probably the most directly related work, Wang et al. [16] propose a system for identifying smart phone apps from encrypted 802.11 frames. They collect data frames from target apps by running them dynamically and training classiﬁers with features from this data. This work shows promise but suffers from the fact that the authors only test 13 arbitrarily chosen apps from eight distinct app store categories and collect network traces for only ﬁve minutes. Indeed, the authors discover that longer training times have an adverse effect on accuracy when classifying some apps with their system. Moreover, the authors use an insufﬁcient sample size (i.e., only 13 apps) to validate their results. By taking into account a large set of apps, in Section 5 (speciﬁcally Fig. 5), we show how increasing the number of apps negatively inﬂuences classiﬁer accuracy. Additionally, it is not known whether Wang et al. chose that speciﬁc set of apps because it offered good classiﬁcation performance or whether a statistically suitable set size will yield similar good performance. The authors also do not provide precision/recall measurements so it is difﬁcult to judge their system performance. Finally, it is problematic to quantify their results, in general, since the authors have no way to collect accurate ground truth, i.e., a labelled dataset that is free of noise from other apps. Indeed, our methodology calls for running a single app at a time to reduce noise, and we still had to ﬁlter out 13% of our raw dataset because it was noise. AppScanner solves the aforementioned problems by going several steps further to systematically investigate this important topic. We use 110 randomly chosen apps (from the most popular apps in the Google Play Store) from 26 different categories and collect network traces for 75 minutes each. We pre-process these network traces using a novel demultiplexing technique to obtain perfect ground truth. We examine two classiﬁcation algorithms, two feature generation approaches, and three overall classiﬁcation strategies. Finally, we identify and validate reasons for trafﬁc misclassiﬁcation and proposemitigation strategies.

 Conti et al. [17] identify speciﬁc actions that users are performing within their smartphone apps. They achieve this through ﬂow classiﬁcation and supervised machine learning. Like AppScanner, their system also works in the presence of encrypted connections since they only leverage coarse ﬂow information such as packet direction and size. The authors achieved more than 95% accuracy for most of the considered actions. This work suffers from its speciﬁcity in identifying discrete actions. By choosing speciﬁc actions within a limited group of apps, Conti et al. may beneﬁt from the more distinctive ﬂows that are generated. Their system does not scale well since a manual approach was taken when choosing and ﬁngerprinting actions. Indeed, the authors had to choose a subset of apps and a subset of actions within those apps to train their classiﬁers on. AppScanner is differ ent in that it has a less speciﬁc classiﬁcation aim (identifying entire apps) and it is highly scalable since ﬁngerprints canbe built for any app automatically.

 St¨ober et al. [18] propose a scheme for ﬁngerprinting entire devices by identifying device-speciﬁc trafﬁc patterns. They contend that 70% of smartphone trafﬁc belongs to background activities happening on the device and that this can be leveraged to create a ﬁngerprint. The authors posit that 3G transmissions can be realistically intercepted and demodulated to obtain side channel information from a transmission such as the amount of transmitted data and the timing. They leverage ‘bursts’ of data to generate features since they cannot analyse the TCP payload directly. Using supervised learning algorithms, the authors build a model of the trafﬁc they want to ﬁngerprint. This model is then capable of identifying similar bursts of data at a later time. The authors conclude that using approximately 15 minutes of captured trafﬁc can result in a classiﬁcation accuracy of over 90%. This work is similar to AppScanner in that they both leverage bursts of trafﬁc to generate ﬁngerprints. How ever, AppScanner is different because we leverage bursts to identify a single speciﬁc app at a time, and are not able to take advantage of the rich information that is present when leveraging multiple interleaved trafﬁc bursts to gain a more unique ﬁngerprint. Additionally, St¨ober et al. [18] need 6 hours of training and 15 minutes of monitoring to achieve reliable ﬁngerprint matching, while AppScanner uses 75 minutes of captured trafﬁc per app for training (which can be done on the attacker’s own device) and can then classifyunknown trafﬁc in real-time.

 3. System Design   

---

 ## 翻译[3/16]：
 

许多作者提出了不同的方案来识别智能手机应用程序和智能手机自身的通信。这些方案依赖于检查IP地址和数据包负载等方法。我们在本文中提出的方法和框架仅使用IP地址来进行流分离（即不用于特征生成，如第3节所述），并且不利用数据包负载中包含的任何信息。Dai等人[15]提出了NetworkProﬁler，一种自动化的方法来使用动态方法进行Android应用程序的调试和识别。他们使用用户界面（UI）模糊技术自动尝试应用程序中的不同执行路径，同时监视网络跟踪。他们检查HTTP负载，因此这种技术存在只能用于未加密流量的缺陷。Dai等人没有完整的地面真实性的流量跟踪数据，因此很难系统地量化NetworkProﬁler在精度、召回率和整体准确性方面的准确性。

在可能是相关性最直接的工作中，Wang等人[16]提出了一种从加密的802.11帧中识别智能手机应用程序的系统。他们通过动态运行目标应用程序并使用这些数据的特征训练分类器来收集数据帧。该工作表现出希望，但存在以下缺陷：作者们仅测试了8个不同应用商店类别中的13个任意选择的应用程序，并仅收集了5分钟的网络跟踪数据。作者们发现，在使用该系统分类某些应用程序时，长时间的训练时间会对准确性产生负面影响。此外，作者们使用的样本大小不足（即仅有13个应用程序）来验证其结果。我们在第5节（特别是图5）中考虑了大量的应用程序，展示了增加应用程序数量如何对分类器准确性产生负面影响。另外，不知道Wang等人选择了那个具体的应用程序集合是否因为该集合具有良好的分类性能，或者是因为一个统计上合适的样本大小将产生类似的好性能。作者们也没有提供精确度/召回率的测量，因此很难判断其系统性能。最后，作者无法量化其结果，因为他们无法收集准确的实际数据集（即标记数据集，没有来自其他应用程序的噪音）。事实上，我们的方法需要一次仅运行单个应用程序以减少噪音，但仍需过滤掉13%的原始数据集，因为其含有噪音。AppScanner通过进一步进行多个步骤来系统地研究这个重要的主题来解决上述问题。我们从26个不同的类别中随机选择了110个应用程序（从Google Play商店中最受欢迎的应用程序），并为每个应用程序收集了75分钟的网络跟踪数据。我们使用一种新颖的分离技术对这些网络跟踪数据进行预处理，以获得完美的真实数据。我们检查了两种分类算法、两种特征生成方法和三种总体分类策略。最后，我们确定并验证了流量误分类的原因，并提出缓解策略。

Conti等人[17]确定了用户在其智能手机应用程序中执行的特定操作。他们通过流分类和监督机器学习实现这一目的。与AppScanner一样，他们的系统也能在加密连接存在的情况下工作，因为他们仅利用如数据包方向和大小等粗略流信息。作者们对大多数考虑的操作实现了95%以上的准确性。这项工作存在其识别离散操作的特定性缺陷。Conti等人通过选择有限数量的应用程序中的特定操作可能受益于更具有特色的流量。他们的系统扩展能力不强，因为选择和指纹识别动作采取了手动方法。事实上，作者们不得不选择应用程序和这些应用程序中的一些动作的子集，以便对其进行训练。AppScanner不同之处在于它具有不太具体的分类目标（识别整个应用程序），并且它非常可扩展，因为指纹可以自动地为任何应用程序进行构建。

St¨ober等人[18]提出了一种通过识别设备特定的流量模式来对整个设备进行指纹识别的方案。他们认为70%的智能手机流量属于设备上正在进行的背景活动，并且这可以被利用来创建指纹。作者认为实际上可以拦截和解调3G传输以从传输中获取侧信道信息，例如传输的数据量和时间等。他们利用数据“尖峰”生成特征，因为他们不能直接分析TCP负载。使用监督学习算法，作者们构建了想要指纹识别的流量的模型。然后，该模型能够在以后的时间识别相似的数据“尖峰”。作者们得出结论，在捕获的大约15分钟的流量数据中使用可以导致超过90%的分类准确性。该工作类似于AppScanner，因为它们都利用数据“尖峰”生成指纹。然而，AppScanner的不同之处在于我们利用数据“尖峰”识别单个特定应用程序，而不能利用多个交错的流量“尖峰”提取更为独特的指纹时提取的丰富信息。此外，St¨ober等人[18]需要6小时的训练和15分钟的监控才能实现可靠的指纹匹配，而AppScanner每个应用程序需要75分钟的捕获流量进行训练（可以在攻击者自己的设备上完成），然后可以实时分类未知流量。

## 

---

 ## 原文[4/16]： 

 
The main idea underpinning AppScanner is the focus on trafﬁc ﬂows from an app that can be used to identify that app. Trafﬁc ﬂows from apps may be interactive or non interactive; that is, they may be generated with or with out user interaction. A newsreader app may generate non interactive trafﬁc ﬂows if it polls a server in the background for the latest news. Interactive trafﬁc ﬂows are generated by user action such as launching an app or navigating the app’s user interface. For our ﬁngerprinting and identiﬁca tion methodology, we focused primarily on interactive app trafﬁc. Our main design goals were: • To develop a highly-scalable framework that could be used to ﬁngerprint and identify smartphone apps. • To ensure that models for new or updated apps could be built in an automated way and added to the system. • To ensure that the models were portable, i.e., they could be built and reused in a new deployment withoutsuffering a penalty for retraining.

 • To deliver a system that could perform real-time (or near real-time) classiﬁcation of ﬂows as they wereobserved on a network.

 3.1. Deﬁnitions 

Before going any further, we deﬁne some terms used later in the paper and explain other key concepts central to theAppScanner framework.

 Burst  A burst is the group of all network packets (irrespective or source or destination address) occurring to gether that satisﬁes the condition that the most recent packet occurs within a threshold of time, the burst threshold, of the previous packet. That is, packets are grouped temporally and a new group is created only when no new packets have arrived within the amount of time set as the burst threshold. This is visually depicted in the Trafﬁc Burstiﬁcation section of Fig. 1, where we can see Burst A and Burst B separated by the burst threshold. We use the concept of a burst to logically divide the network trafﬁc into discrete, manageable portions, which can then be further processed. The concept of a burst was previously used by St¨ober et al. [18] and isused similarly here.

 Flow  A ﬂow is a sequence of packets (within a burst) with the same destination IP address and port number. That is, within a ﬂow, all packets will either be going to (or coming from) the same destination IP address/port. Flows are not to be confused with TCP sessions. A ﬂow ends at the end of a burst, while a TCP session can span multiple bursts. Thus, ﬂows typically last for a few seconds, while TCP sessions can continue indeﬁnitely. AppScanner leverages ﬂows instead of TCP sessions to achieve real-time/nearer-to-real-time classiﬁcation. From the Flow Separation section of Fig. 1, we can see that a burst may contain one or more ﬂows. Flows may overlap in a burst if a single app, App X, initiates TCP sessions in quick succession or if another app, App Y, happens to initiate a TCP session at the same time as App X. We explain how we accurately attribute ﬂows to their originating app in Section 3.3. The notion of ﬂows has been used previously by Conti et al. [17] and are usedsimilarly here.  

---

 ## 翻译[4/16]：
 

AppScanner的主要思想是专注于可以用于识别应用程序的应用程序流量。应用程序流量可以是交互式或非交互式的；也就是说，它们可以是有或没有用户交互生成的。如果新闻阅读器应用程序在后台轮询服务器获取最新新闻，则可能会生成非交互式的应用程序流量。交互式的应用程序流量则是由用户操作生成的，例如启动应用程序或浏览应用程序的用户界面。我们的指纹和识别方法主要集中在交互式应用程序流量上。我们的主要设计目标是：

• 开发一个可高度伸缩的框架，可以用于指纹识别智能手机应用程序。

• 确保新的或更新的应用程序模型可以以自动化的方式构建并添加到系统中。

• 确保这些模型是可移植的，即它们可以在新的部署中构建和重复使用，而不必重新训练。

• 提供一个系统，可以实时（或接近实时）地对网络中观察到的流进行分类。

# 3.1. 定义

在继续之前，我们定义一些本文后面使用的术语，并解释AppScanner框架中的其他关键概念。

 Burst 爆发 是所有网络数据包（无论源地址或目的地址）一起发生，满足最近的数据包在前一数据包的阈值时间内的条件，即仅在没有新数据包到达设置为爆发阈值的时间数量时才会创建新组。这在图1的Trafﬁc Burstiﬁcation部分中有直观的描述，我们可以看到Burst A和Burst B由爆发阈值分隔。我们使用爆发的概念将网络流量逻辑上分成离散的可管理部分，然后进一步进行处理。爆发的概念先前由St¨ober等人使用[18]，在此类似使用。

 Flow 流 是具有相同目标IP地址和端口号的数据包序列（在爆发中）。也就是说，在流中，所有数据包要么将要（或来自）相同的目标IP地址/端口。流不应与TCP会话混淆。流在爆发结束时结束，而TCP会话可以跨越多个爆发。因此，流通常持续几秒钟，而TCP会话可以无限期地继续进行。AppScanner利用流而不是TCP会话来实现实时/近实时的分类。从图1的Flow Separation部分中，我们可以看到一个爆发可能包含一个或多个流。如果单个应用程序App X快速连续启动TCP会话，或者如果另一个应用程序App Y恰好在App X同时启动TCP会话，则流可能会在一个爆发中重叠。我们将在第3.3节中解释如何准确地将流归属于它们的起源应用程序。 Conti等人以前使用了流的概念[17]，在此也类似使用。

## 

---

 ## 原文[5/16]： 

 
 We use supervised machine learning for pattern recog nition on ﬂows. In AppScanner, the supervised learning algorithms are provided with labelled examples of ﬂows (or statistical features extracted from these ﬂows) from each app which are then used to build models. These models can then be used to classify unlabelled ﬂows. The models need to be lightweight since we need AppScanner to be deploy able even in environments with limited processing/memory resources and still perform app classiﬁcations in real-timeor near real-time.

 3.2. Equipment Setup 

The setup used to collect network traces from apps is shown in the Equipment Setup section of Fig. 1. The workstation was conﬁgured to forward trafﬁc between the Wi-Fi access point (AP) and the Internet. To generate trafﬁc from which to capture our training data, we used scripts that communicated with the target smartphone via USB using the Android Debug Bridge (ADB). These scripts were used to simulate user actions on the test device and thus elicit network ﬂows from the apps. Trafﬁc ﬂowing through the workstation was captured and exported to a comma separated value (CSV) ﬁle with each row containing the details of a captured packet. We collected packet details such as time, source address, destination address, ports, packet size, protocol and TCP/IP ﬂags. The payload for each packet was also collected but was not used to provide features since it may or may not be encrypted. Our aim is for AppScanner to be able to identify apps whether their trafﬁc is encrypted or unencrypted. Although physical hardware was used for network trafﬁc generation and capturing, this process can be massively automated and parallelized by running apps within Android emulators on virtual machines.

 3.3. Fingerprint Making 

The ﬁngerprint making process consisted of a number of steps that we outline in Fig. 1, and describe below. Network Trace Capture: The Network Trace Capturing process entailed running user simulation scripts on the hard ware setup. These scripts generated app launches, touches and button presses to elicit interactive trafﬁc from apps which was then collected using a packet sniffer. We ran only one app at a time to minimise ‘noise’ in the network traces. We observed that all the apps in our test set generated network ﬂows when they were launched. User simulation can be done in various ways, but we leveraged the standard Android SDK UI exerciser tools, monkey and monkeyrunner. AppScanner does not leverage patterns of ﬂows or other such artefacts that may be emphasized in human-generated app trafﬁc. For this reason, we can automate the training process (for high-scalability) using UI exercising tools. The use of UI automation may cause us to not obtain all of an app’s unique ﬂows, but the ﬂows that are obtained would still be real-world trafﬁc ﬂows that would have come from the app if a human user were using it. For example, an app would still check-in with its server, send standard API queries, load online resources, and other similar tasks. In general, the more diverse the connections an app makes, the more distinguishing the trafﬁc will be when used for feature generation and the subsequent training of classiﬁers. Figure 1: Visualisation of bursts and ﬂows within TCP/IP trafﬁc, and a high-level representation of the classiﬁer train-ing steps performed by AppScanner.

 Greater coverage of all the network ﬂows in an app may theoretically be obtained by using advanced UI fuzzing techniques provided by frameworks such as Dynodroid [19], or by recruiting human participants. However, we consider these approaches to be out of scope for this paper. After data collection, the network trafﬁc dumps were ﬁltered to include only TCP trafﬁc that was error free. For example, we ﬁltered to remove packet retransmissions that were as a result of network errors. However, these dumps potentially contained trafﬁc from other Android apps running (in the background) on the smartphone that could interfere with and taint the ﬁngerprint making process. In addition to the target apps, another open-source app, Network Log [20], was installed and started on the target device. Network Log was used to identify the app responsible for each network ﬂow coming from the test device. In this way, we obtained perfect ground truth of what ﬂows came from what app. Using logged data from Network Log combined with a ‘demultiplexing’ script, all trafﬁc that did not originate from the target app was removed from the trafﬁc dump for that app. At this point, each network dump only contained error-free TCP trafﬁcfrom the target app.  

---

 ## 翻译[5/16]：
 

我们使用监督式机器学习用于流量的模式识别。在AppScanner中，监督学习算法提供了每个应用程序的标记流量示例（或从这些流量中提取的统计特征），然后用于构建模型。这些模型可以用于对没有标签的流量进行分类。由于我们需要在处理/内存资源有限的环境中部署AppScanner，并仍能在实时或准实时中执行应用程序分类，因此模型需要轻量级。

＃3.2 装备设置

收集应用程序的网络跟踪所使用的设置显示在图1的“装备设置”部分。工作站被配置用于在Wi-Fi接入点（AP）和互联网之间转发流量。为了生成可用于捕获训练数据的流量，我们使用了通过使用Android Debug Bridge（ADB）通过USB与目标智能手机通信的脚本。这些脚本用于模拟对测试设备上的用户操作，从而引出应用的网络流量。从工作站流过的流量被捕获并导出到以逗号分隔的值（CSV）文件中，其中每行包含捕获的数据包的详细信息。我们收集数据包的详细信息，如时间，源地址，目标地址，端口，包大小，协议和TCP / IP标志。每个包的有效载荷也被收集，但未用于提供特性，因为它可能是加密的或非加密的。我们的目标是使AppScanner能够识别应用程序，无论其流量是否加密。虽然物理硬件用于网络流量的生成和捕获，但此过程可通过在虚拟机上运行Android模拟器中的应用程序来进行大规模自动化和并行化。

＃3.3 指纹制作

指纹制作过程包括很多步骤，我们在图1中概述了这些步骤，并在下面进行了描述。

网络跟踪捕获：网络跟踪捕获过程涉及在硬件设置上运行用户模拟脚本。这些脚本生成应用程序启动、触摸和按键操作，以引出应用程序的交互式流量，然后使用数据包嗅探来收集这些流量。我们一次仅运行一个应用程序，以最小化网络跟踪中的“噪音”。我们观察到，在测试集中的所有应用程序在启动时都会生成网络流量。用户模拟可以以各种方式进行，但是我们利用了标准的Android SDK UI exerciser工具monkey和monkeyrunner。AppScanner不利用人工生成的应用程序流量中可能强调的流模式或其他类似的特征物，并且因此我们可以使用UI练习工具自动化训练过程（以实现高可扩展性）。使用UI自动化可能导致我们没有获取应用程序的所有唯一流量，但所获得的流量仍然是从应用程序中得出的真实世界流量，如果人类用户在使用它，应用程序仍然会与其服务器进行检查，发送标准API查询，加载在线资源和执行其他类似的任务。一般来说，应用程序制造的连接越多，当用于特征生成和随后的分类器训练时，这些流量将具有越大的区别性。理论上，可以通过使用如Dynodroid [19]等框架提供的高级UI模糊技术或招募人类参与者来获得应用程序中所有网络流量的更全面覆盖，但是我们认为本文不涵盖这些方法。在数据收集之后，网络流量转储会被过滤，仅包括没有错误的TCP流量。例如，我们过滤掉由于网络错误而导致的数据包重传。但是，这些转储潜在地包含来自智能手机上运行的其他Android应用程序的流量（在后台运行），可能会干扰和污染指纹制作过程。除目标应用程序之外，另一个开源应用程序Network Log [20] 在目标设备上安装并启动。 Network Log用于识别来自测试设备的每个网络流量源自哪个应用程序。通过使用Network Log记录的数据组合“解复用”脚本，将全部不是由目标应用程序发起的流量从该应用程序的流量转储中删除。此时，每个网络转储仅包含来自目标应用程序的无错误TCP流量。

## 

---

 ## 原文[6/16]： 

 
 Trafﬁc Burstiﬁcation and Flow Separation: The next step was to parse the network dumps to obtain network trafﬁc bursts. Trafﬁc was ﬁrst discretized into bursts to obtain ephemeral chunks of network trafﬁc that could be sent immediately to the next stage of AppScanner for processing. This allows us to meet the design objective of real-time or near real-time classiﬁcation of network trafﬁc. Falaki et al. [21] observed that 95% of packets on smartphones “are received or transmitted within 4.5 seconds of the previous packet”. During our tests, we observed that setting the burst threshold to one second instead of 4.5 seconds only slightly increased the number of bursts seen in the network traces. This suggested to us that network performance (in terms of bandwidth and latency) has improved since the original study. For this reason, we opted to use a burst threshold of one second to favour more overall bursts and nearer to-real-time performance. These bursts were separated into individual ﬂows (as deﬁned in Section 3.1 and depicted in Fig. 1) using destination IP address/port information. We enforced a minimum ﬂow length and maximum ﬂow length that would be considered by AppScanner. This is simply to ensure that AppScanner safely ignores abnormal trafﬁcwhen deployed in the real-world.

 It is important to note that while destination IP addresses were used for ﬂow separation, they were not leveraged to assist with app identiﬁcation. We also opted to not use information gleaned from DNS queries or ﬂows with un encrypted payloads. These were deliberate design decisions taken to understand how AppScanner would perform in the worst case, as well as avoid the reliance on domain-speciﬁc knowledge that frequently changes. Concretely, these addi tional sources of data may be considered unsuitable for the following reasons: • IP addresses  Destination IP addresses contacted by an app can change if DNS-based load-balancing/high availability is used. Additionally, many apps contact similar IP addresses because they utilise the same CDNor belong to the same developer.

 • DNS queries  DNS queries are not always sent/observed due to the use of client-side DNS caching. Also, multiple apps may send the same DNS queries, for example, to resolve advertisement serverdomain names.

 • Packet payloads  Many app developers are becoming more privacy-aware and are opting to use HTTPS/TLS to encrypt packet payloads. Thus features extracted from TCP payloads will become less useful over time. While the aforementioned data sources may be carefully used to assist with app identiﬁcation, we consider their use to be out of scope for this paper and leave such analysis tofuture work.

 Feature Extraction and Classiﬁer Training: Once we obtained individual ﬂows falling within the prescribed ﬂow length thresholds, features were generated from them and used to train classiﬁers. Raw packet lengths from ﬂows were used as features, as well as the statistical properties of these ﬂows. We elaborate on feature generation and classiﬁcationapproaches/strategies in Section 4.

 3.4. Fingerprint Matching   

---

 ## 翻译[6/16]：
 

流量爆发和流分离：接下来，我们需要解析网络转储以获取网络流量爆发。首先将流量离散化为爆发，从而获取短暂网络流量块，这些块可以立即发送到AppScanner的下一阶段进行处理。这使我们可以实现实时或接近实时的网络流量分类设计目标。Falaki等人观察到智能手机上95％的数据包“在上一个数据包到达或发送后的4.5秒内收到或发送”。在我们的测试中，我们观察到将爆发阈值设置为1秒而不是4.5秒只稍微增加了网络跟踪中看到的爆发数量。这向我们暗示了网络性能（带宽和延迟方面）自原研究以来有所提高。因此，我们选择使用1秒的爆发阈值，以更有利于更多的总体爆发和接近实时的性能。使用目标IP地址/端口信息将这些爆发分解为单独的流（如第3.1节所定义并在图1中表示的）。我们对AppScanner将考虑的最小流长度和最大流长度执行了强制规定。这仅仅是为了确保在实际部署时AppScanner安全地忽略异常流量。

需要注意的是，虽然我们使用目标IP地址进行流分离，但这些地址并未被用于帮助应用程序识别。我们还选择不使用从DNS查询或未加密有效载荷的数据中获取的信息。这些都是有意识的设计决策，旨在了解AppScanner在最坏情况下的性能，并避免过多依赖经常变化的特定于域的知识。具体来说，出于以下原因，这些附加数据源可能被认为不适合：

• IP地址  如果使用基于DNS的负载平衡/高可用性，则应用程序联系的目标IP地址可能会更改。 此外，许多应用程序联系相似的IP地址，因为它们使用相同的CDN或属于同一开发人员。

• DNS查询  由于使用客户端DNS缓存，DNS查询并不总是被发送/观察到。 此外，多个应用程序可能发送相同的DNS查询，例如解析广告服务器域名。

•数据包有效载荷  许多应用程序开发人员正在变得更加关注隐私，并选择使用HTTPS / TLS对数据包有效载荷进行加密。因此，从TCP有效载荷中提取的特征随着时间的推移将变得越来越不有用。虽然上述数据源可以小心地用于协助应用程序识别，但我们认为它们的使用不在本文的范围之内，并将这样的分析留给未来的工作。

特征提取和分类器培训：一旦我们获得了符合规定流程长度阈值的单个流，就会从中生成特征并用于培训分类器。原始数据包长度从流中用作特征，以及这些流的统计特性。我们在第4节中详细阐述了特征生成和分类方法/策略。

3.4. 指纹匹配

## 

---

 ## 原文[7/16]： 

 
The ﬁngerprint matching phase follows steps similar to those of the ﬁngerprint making phase, up to the end of the feature extraction step. At this point, the features are instead passed to the pre-built models to be classiﬁed, followed by what we call the ‘classiﬁcation validation’ phase at the end. During ﬁngerprint matching, the network trafﬁc capturing phase is also somewhat different, since we may perform ﬁngerprint matching during a live networkcapture or on a saved network trace.

 Network Trafﬁc Capturing: AppScanner can work in both online and ofﬂine mode for capturing and processingnetwork trafﬁc.

 • Online Mode  Network trafﬁc from the target smart phone is sniffed directly from the air on a live network using tshark (the terminal version of Wireshark) or a similar tool and passed on to the trafﬁc capturing module of AppScanner by means of a tshark wrap per library. The trafﬁc burstiﬁcation buffer collects the incoming network packets and passes them on to the ﬂow separation module as a burst whenever the burst threshold amount of time elapses with no new packets being seen. Thus, AppScanner performs app identiﬁcation in real-time or near real-time. • Ofﬂine Mode  A pre-collected network trace can be fed into AppScanner for ‘batch processing’. The network trace is parsed into bursts and passed on to the ﬂow separation module just as in online mode. TCP Pre-processing and Flow Classiﬁcation: The ﬂow separation module, upon receiving a burst of network trafﬁc, uses source and destination IP addresses to separate it into ﬂows. Before ﬂows are passed on to the next stage in AppScanner, they are discarded if they contain any TCP retransmissions or other errors or if they fall outside of the ﬂow length thresholds. Flows containing TCP retransmissions or other errors are discarded since they would introduce noise into the ﬂow that should not be there. As mentioned before, ﬂow length thresholds are set to ensure that very lengthy (and most likely anomalous) ﬂows do not enter the system. We discuss the actual ﬂow length thresholds used in Section 5. Feature generation (see Fig. 2 for an outline of how this is done) is performed on these error-free, validated ﬂows and the features of each ﬂow are passed on to the classiﬁers for identiﬁcation. The result of this classiﬁcation is then passed to the ﬁnal phase,called classiﬁcation validation.

 Classiﬁcation Validation: The classiﬁcation validation stage is crucial for one primary reason. Machine learning al gorithms will always attempt to place an unlabelled example into the class it most closely resembles, even if the match is not very good. Given that our classiﬁers will never be trained with the universe of ﬂows from apps, it follows that there will be some ﬂows presented to AppScanner which are simply unknown or never-before-seen. If left unchecked, this can cause an undesirable increase in the false positive (FP) rate. Additionally, as we discuss in Section 5, some trafﬁc ﬂows from different apps are very similar to each other, and this will also cause an undesirable increase in the FP rateof AppScanner if left unchecked.

 To counteract these problems, we leverage the prediction probability feature available in the classiﬁers to understand how certain the classiﬁer is about each of its classiﬁca tions. The prediction probability is a measure reported by a classiﬁer that gives an indication of how conﬁdent the classiﬁer is about its assignment of a particular label to an unknown sample. For example, if the classiﬁer labelled an unknown sample as com.facebook.katana, we would check its prediction probability value for that classiﬁcation to determine the classiﬁer’s conﬁdence. If this value is below the classiﬁcation validation threshold, AppScanner will not make a pronouncement. However, if this value exceeds the threshold, AppScanner would report it as a match for that particular app. In Section 5, we discuss how varying this threshold impacts the precision, recall, and overall accuracy of AppScanner, as well as how this affects the percentage of total ﬂows that the classiﬁers are conﬁdent enough toclassify.

 4. Classiﬁer Design   

---

 ## 翻译[7/16]：
 

指纹匹配阶段与指纹生成阶段的步骤类似，直到特征提取步骤的末尾。此时，特征被传递到预先构建的模型中进行分类，然后在末尾进行‘分类验证’阶段。在指纹匹配期间，网络流量捕获阶段也略有不同，因为我们可以在实时网络捕获或保存的网络跟踪上执行指纹匹配。

网络流量捕获：AppScanner可以在在线和离线模式下工作，用于捕获和处理网络流量。

• 在线模式：从目标智能手机中直接捕获来自现场网络的网络流量，使用tshark（Wireshark的终端版本）或类似工具直接将其传递给AppScanner的流量捕获模块，方法是使用tshark的包装库。流量突发缓冲区收集传入的网络数据包，并在Burst阈值时间没有看到新数据包时作为突发流传递到流分离模块。因此，AppScanner可以实时或接近实时地执行应用程序识别。

• 离线模式：可以将预先收集的网络跟踪馈入AppScanner进行‘批处理’。网络跟踪被解析成突发流，然后像在线模式那样传递到流分离模块。TCP预处理和流分类：在接收到网络流量的Burst时，流分离模块使用源IP地址和目标IP地址将其分为各个流。在将流传递给AppScanner的下一阶段之前，如果流中包含任何TCP重传或其他错误或者流通信超过流长度阈值，则会被丢弃。由于存在潜在的干扰噪声，流中包含TCP重传或其他错误的流被丢弃。如前所述，流长度阈值被设置以确保非常长（极有可能是异常）的流不进入系统。在第5节中，我们将讨论实际使用的流长度阈值。这些经过验证的无错误流上执行特征生成（请参见图2以了解如何执行此操作），并将每个流的特征传递给用于识别的分类器。分类器的结果随后传递给最终阶段，称为分类验证。

分类验证阶段之所以至关重要，原因在于：机器学习算法始终会尝试将未标记的示例放入最接近的类别，即使匹配不太好。鉴于我们的分类器永远不会被训练为识别应用程序所有可能存在的流，因此会出现一些向AppScanner提交的根本未知或从未在以前看到的流。如果不予检查，这可能会导致假阳性（FP）率不佳的提高。此外，如第5节中所讨论的，不同应用程序的某些流非常相似，如果不予检查，也会导致AppScanner的FP率不佳的提高。

为了解决这些问题，我们利用分类器可用的预测概率特征，以了解分类器在每个分类上的确信度。预测概率是由分类器报告的度量，它指示分类器对于给定标记分配给未知样本的信心程度。例如，如果分类器将未知样本标记为com.facebook.katana，则我们将检查该分配的预测概率值，以确定分类器的确信度。如果此值低于分类验证阈值，则AppScanner不会进行判断。但是，如果此值超过阈值，则AppScanner将报告它与该特定应用程序的匹配。在第5节中，我们将讨论如何改变此阈值会影响AppScanner的精度、召回率和总体准确度，以及这将如何影响分类器有信心分类的总流量百分比。

# 4.分类器设计

## 

---

 ## 原文[8/16]： 

 
Since AppScanner is modular, it is possible to use different machine learning algorithms with minimal ef fort required if modiﬁcations are made. We designed and thoroughly tested six classiﬁcation approaches as shown in Table 1. Each approach used either a Support Vector Classiﬁer (SVC) or a Random Forest Classiﬁer. These two classiﬁers were chosen because they are particularly suited for predicting classes (in our case, apps) when trained with the features that we extracted from network ﬂows. A Support Vector Classiﬁer models training examples as points in space, and then divides the space using hyperplanes to give the best separation among the classes. In the case of non-linearly separable problems, the Support Vector Classi ﬁer can rely on kernel functions to project the data into a high-dimensional feature space to make it linearly separable. A Random Forest Classiﬁer is an ensemble method that uses multiple weaker learners to build a stronger learner. This classiﬁer constructs multiple decision trees during training and then chooses the mode of the classes output by the individual trees. It is also able to rank the importance of the features that it has selected for use (as shown in Table 3). In Table 2, we outline additional characteristics of each of the six classiﬁcation approaches that show why one would favour a particular approach over another. The classiﬁers are compared in terms of their speed of training, size of classiﬁer, average conﬁdence per classiﬁcations, whether they can measure true negatives, and whether they are robust against out-of-order packets. In general, the Per Flow Length Classiﬁers are smaller and faster to train since they have smaller training sets (only ﬂows of a certain length). We include average speeds and sizes for the approaches when trained using our dataset. Only the binary classiﬁers are able to understand true negatives. Only the classiﬁers using statis tical features are robust against out-of-order packets because the other classiﬁers would incorrectly assign features whenpresented with swapped packets.

 The features used to train the classiﬁers were either the actual ﬂow vectors of raw packet lengths or statistical features derived from these ﬂow vectors. Fig. 2 shows broadly the two approaches of using ﬂow vectors or statisti cal features. From the ﬁgure, the ﬂow pre-processor simply changes the sign (i.e., makes negative) the length of incom ing packets. The output of the ﬂow pre-processor is then passed as a (variable length) ﬂow vector to the classiﬁers that use packet lengths as features, or to the Statistical Feature Extraction function for the other classiﬁcation strategies. Statistical Feature Extraction involves deriving 54 sta tistical features from each ﬂow (regardless of ﬂow length). For each ﬂow, three packet series are considered: incoming packets only, outgoing packets only, and bi-directional trafﬁc (i.e. both incoming and outgoing packets). For each series (3 in total), the following values were computed: minimum, maximum, mean, median absolute deviation, standard de viation, variance, skew, kurtosis, percentiles (from 10% to 90%) and the number of elements in the series (18 in total). These statistical features were computed using the Pythonpandas libraries [22].

 The features were then passed through the Feature Scaler function, which is a min-max scaler (i.e., the minimum and the maximum value for a speciﬁc feature in the training set corresponds to 0 and 1 respectively). In order to avoid the curse of dimensionality, a Feature Selection function was used to choose the best features. The TABLE 1: The six different classiﬁcation approaches that were tested in AppScanner. TABLE 2: Additional characteristics of the six classiﬁcation approaches that would help one to determine what approach is more suitable for their particular deployment. RF means Random Forest Classiﬁer. Large SVC and Large RF refer to Approaches 3 and 4 each having a Single Large Classiﬁer. Avg. conﬁdence per classiﬁcation was determined based on theresults of our extensive tests.  

---

 ## 翻译[8/16]：
 

由于AppScanner是模块化的，如果进行修改，就有可能使用不同的机器学习算法而仅需最小的努力。正如表1所示，我们设计并经过了充分的测试6种分类方法。每种方法都使用了支持向量分类器（SVC）或随机森林分类器。我们选择这两个分类器是因为它们特别适合根据从网络流中提取的特征训练来预测类别（在我们的情况下，应用程序）。支持向量分类器将训练例子建模为空间中的点，然后使用超平面将空间分割以在类别之间获得最佳分离。在非线性可分问题的情况下，支持向量分类器可以依靠核函数将数据投影到高维的特征空间中使其线性可分。随机森林分类器是一种集成方法，它使用多个较弱的学习器来构建一个更强大的学习器。这个分类器在训练期间构建多个决策树，然后选择个体树输出的类别的模式。它还能够对其选择使用的特征进行排名（如表3所示）。在表2中，我们概述了每种6个分类方法的其他特性，从而说明为什么一个人会偏向于使用一个特定的方法而不是另一个方法。这些分类器以训练速度、分类器大小、每个分类的平均置信度、它们是否能够测量真负面和它们是否能够抵抗打乱顺序的包等方面进行比较。总的来说，每个流长度分类器都更小、更快，因为它们具有较小的训练集（只有特定长度的流）。我们使用我们的数据集对这些方法进行训练时，考虑了它们的平均速度和大小。只有二进制分类器能够理解真负面。仅使用统计特征的分类器才能抵御混乱的包，因为其他分类器在出现交换包的情况下会错误地分配特征。

用于训练分类器的特征是原始包长度的实际流向量或从这些流向量中派生的统计特征。图2广泛展示了两种使用流向量或统计特征的方法。从图中可以看出，流预处理器仅改变入站包的长度（即使其为负数）。流预处理器的输出随后作为（可变长度的）流向量传递给使用数据包长度作为特征的分类器，或者传递给其他分类策略的统计特征提取函数。统计特征提取涉及从每个流中导出54种统计特征（无论流的长度如何）。对于每个流，考虑三个数据包系列：仅入站数据包、仅出站数据包和双向流量（即入站和出站数据包）。对于每个系列（共3个），计算以下值：最小值、最大值、平均值、中位数绝对偏差、标准偏差、方差、偏斜、峰度、分位数（从10%到90%）以及系列中的元素数量（共18项）。使用Python Pandas库[22]计算这些统计特征。然后通过特征缩放器函数将特征传递，该函数是一个最小-最大缩放器（即训练集中特定特征的最小值和最大值分别对应于0和1）。为了避免维度的诅咒，使用Feature Selection函数选择最佳特征。 表格1：在AppScanner中测试的六种不同分类方法。表格2：六种分类方法的其他特点，这些特点有助于确定哪种方法更适合特定的部署。RF代表随机森林分类器。大SVC和大RF指的是Approach 3和Approach 4各自具有单一大分类器。基于我们广泛的测试结果，确定每种分类的平均置信度。

## 

---

 ## 原文[9/16]： 

 
 Feature Selection function leverages the Gini Importance metric used by a Random Forest classiﬁer that was run on the training set [23]. This metric relies on the Gini impurity index which is computed during estimator building. At the end of training, the classiﬁer gave a score to each feature according to its signiﬁcance. At this point, we selected only those features with a score higher than 1%, for a total of 40 features of the original 54. In Table 3, we report the score for each of the Top 40 features. Approach 1-2  Multi-Class Classiﬁcation using a Classiﬁer Per Flow Length: These approaches involve training a multi-class Support Vector Classiﬁer and a Random Forest Classiﬁer with the features being a vector of packet sizes from each ﬂow. For the Support Vector Classiﬁer, we used an rbf kernel with parameters gamma=0.0001, C=10000. For the Random Forest Classiﬁer, we used parameters criterion=gini, max features=None, n estimators=150. An exhaustive search on a wide set of hyperparameters (with 5-fold cross-validation) was used to optimize these parameters. The length of the feature array from a ﬂow is equal to the amount of packets in the ﬂow and thus the classiﬁer for ﬂow length n will be trained with n features per training example. Only one classiﬁer per ﬂow length is possible (since each training example in a classiﬁer needs to have the same amount of features) and thus we have up to the maximum ﬂow length amount of classiﬁers. Approach 3-4  Multi-Class Classiﬁcation using a Single Large Classiﬁer: These approaches involve training a multi-class Support Vector Classiﬁer and a Random Forest Classiﬁer with the features being statistical features derived from the vector of packet sizes from each ﬂow. In these approaches, each classiﬁer is very large and contains all the apps in the test set of apps. The parameters for the Support Vector Classiﬁer were kernel=linear,C=100.

 For the Random Forest Classiﬁer, we used parameters criterion=gini, max features=sqrt, n estimators=150. An exhaustive search on a wide set of hyperparameters (with 5-fold cross-validation) was used to optimize theseparameters.

 Approach 5-6  Binary Classiﬁcation using a Single Classiﬁer Per App: These approaches involve training a binary Support Vector Classiﬁer and a binary Random Forest Classiﬁer with the features being statistical features derived from the vector of packet sizes from each ﬂow. For the Support Vector Classiﬁer, we used an rbf kernel with gamma=0.001, C=100. For the Random Forest Classiﬁer, we used parameters n estimators=10. In these approaches, each classiﬁer was a binary classiﬁer and was trained to identify only one app. Since the classiﬁers were of a binary nature, unlabelled ﬂows were passed to each of the 110 classiﬁers in parallel when they were to be classiﬁed. After training the classiﬁers, the models were saved to a persistent state using serialization. By serializing the trained classiﬁers, they could be loaded almost instantly the next time they were used without suffering a penalty for retrain-ing.

 5. System Evaluation 

In this section, we present the experiment settings and the results of the tests that we performed on AppScanner. To build and test our framework, we used a Motorola XT1039 (Moto G) smartphone running Android 4.4.4 (KitKat). The smartphone was connected to the internet via a Linksys E1700 Wi-Fi Router/AP that had its internet connection routed through a Dell Optiplex 9020 workstation with two network interface cards. Each app was exercised automati cally (using the procedure outlined in Section 3.2) in 150 rounds for a period of 75 minutes and the resulting net work trafﬁc was collected using Wireshark. We built the classiﬁers in Python using the scikit-learn machine learning Figure 2: Feature Extraction from ﬂows  AppScanner’s two main approaches for generating features from ﬂows for classiﬁertraining.  

---

 ## 翻译[9/16]：
 

特征选择函数利用在训练集上运行的随机森林分类器使用的Gini重要性指标[23]。这个指标依赖于基尼杂质指数，在估计器构建期间计算。在训练结束时，分类器给每个特征打分以衡量其重要性。此时，我们仅选择那些得分高于1%的特征，共选择原始54个特征中的40个。在表3中，我们报告了前40个特征的得分。方法1-2：使用每个流的长度一个分类器的多类分类。这些方法包括使用一个由每个流的数据包大小向量构成的特征向量训练多类支持向量分类器和随机森林分类器。对于支持向量分类器，我们使用rbf内核，参数为gamma=0.0001，C=10000。对于随机森林分类器，我们使用criterion=gini，max features=None，n estimators=150的参数。我们使用广泛的超参数集（5倍交叉验证）进行了详尽的搜索以优化这些参数。来自流的特征数组的长度等于流中数据包的数量，因此流长度为n的分类器将使用每个训练示例的n个特征进行训练。每个流长度只能有一个分类器（因为每个分类器中的每个训练示例需要具有相同数量的特征），因此我们最多有流最大长度的数量的分类器。方法3-4：使用单个大分类器的多类分类。这些方法包括使用从每个流的数据包大小向量派生出的统计特征训练多类支持向量分类器和随机森林分类器。在这些方法中，每个分类器都非常大，包含测试应用程序集中的所有应用程序。支持向量分类器的参数为kernel=linear，C=100。对于随机森林分类器，我们使用criterion=gini，max features=sqrt，n estimators=150的参数。我们使用广泛的超参数集（5倍交叉验证）进行了详尽的搜索以优化这些参数。方法5-6：使用每个应用程序一个分类器的二元分类。这些方法包括使用从每个流的数据包大小向量派生出的统计特征训练二进制支持向量分类器和二进制随机森林分类器。对于支持向量分类器，我们使用rbf内核，参数为gamma=0.001，C=100。对于随机森林分类器，我们使用n estimators=10的参数。在这些方法中，每个分类器都是二进制分类器，只训练识别一个应用程序。由于分类器是二进制的，当它们被分类时，未标记的流被同时传递到110个分类器中的每一个。在训练分类器后，通过序列化将模型保存到一个持久状态中。通过序列化训练过的分类器，它们可以在下一次使用时快速加载，而无需重新训练的惩罚。

在本节中，我们介绍了在AppScanner上执行的测试的实验设置和结果。为了构建和测试我们的框架，我们使用一个运行Android 4.4.4（KitKat）的Motorola XT1039（Moto G）智能手机。智能手机通过一个Linksys E1700 Wi-Fi路由器/AP连接到互联网，这个路由器的互联网连接通过一个Dell Optiplex 9020工作站的两个网络接口卡进行路由。每个应用程序在75分钟的150轮中自动实验（使用第3.2节中概述的过程），并使用Wireshark收集所产生的网络流量。我们使用Python中的scikit-learn机器学习构建分类器。图2：AppScanner从流中提取特征的两种主要方法进行分类器训练。

## 

---

 ## 原文[10/16]： 

 
 TABLE 3: Table showing the percentage scores given to the 40 statistical features which exceeded the threshold of 1%. libraries [24]. At the end of the training process, the clas siﬁers were serialized in a process called pickling. Pickling is a feature provided by Python that allows the translation of the classiﬁer data structures and object state into ﬁles. The aim of the experiment was to ﬁnd out how accu rately we could ﬁngerprint and re-identify apps from their interactive trafﬁc as captured from the network. For these tests, AppScanner was trained with interactive trafﬁc from 110 apps. These apps were chosen at random from the 150 Top Free Apps as listed in the Google Play Store in July 2015. (Please see Table 9 in the Appendix for the list of apps that were used to test AppScanner.) We chose the most popular apps because we believe that these apps represent a very large cross-section of the total install base of apps across the world. If AppScanner performs well on these apps, it points to the usefulness of AppScanner as a framework for identifying apps on a global scale. Furthermore, we used free apps because free apps tend to contain more advertisements than paid apps and thus would generate more advertisement trafﬁc. Since advertisement trafﬁc supplied by a particular ad network would tend to be similar, AppScanner would have a more difﬁcult task in classifying advertisement ﬂows as belonging to one app from the group of apps that use the same ad network. Indeed, our results conﬁrm this. For this reason, we believe the results we obtain from AppScanner being tested on free apps is the worst case performance ﬁgure.

 5.1. Measuring AppScanner’s Performance 

Before training the classiﬁers, we needed to choose a suitable value for the minimum ﬂow length that would be considered. For this test, we chose our Per Flow Random Forest Classiﬁer (Approach 2) and varied the minimum ﬂow length threshold while keeping the maximum ﬂow length threshold constant at inﬁnity. Fig. 3 shows the effect that changing minimum ﬂow length had on classiﬁcation accuracy. Classiﬁer accuracy increased sharply from a ﬂow length of one packet to a ﬂow length of seven packets and remained constant (more or less) afterwards. This is understandable since shorter ﬂows carry less information, and as a result, we expect the classiﬁers to make more errors when classifying shorter ﬂows. A ﬂow length of seven is a good choice of minimum ﬂow length because it is the length of the shortest “complete” ﬂow; i.e., a ﬂow containing a TCP handshake (three packets) followed by an HTTP request, Figure 3: Impact of minimum ﬂow length on classiﬁer accuracy for the Per Flow Random Forest Classiﬁer. response, and acknowledgements (four packets). Note that we do not consider TCP session termination packets in the length of a shortest complete ﬂow. This is because the burst threshold will usually occur before the TCP session termination packets, and as such they would never be a part of a ﬂow. For these reasons, a minimum ﬂow length of seven was used for the remainder of the tests. Of course, this can be easily adjusted based on any other speciﬁc needs. The other classiﬁcation approaches yielded plots with a similar behaviour for classiﬁer accuracy vs. minimum ﬂow lengthand are omitted for brevity.

 Using a minimum ﬂow length of seven and an arbi trary maximum ﬂow length of 260, our interactive trafﬁc contained 131,736 ﬂows which was split 75%/25% for the training/testing sets respectively. We used a maximum ﬂow length of 260 since this was the length of the longest ﬂow observed in our training data. This value can be easily adjusted depending on the maximum ﬂow length expected in a typical usage scenario. We trained the classiﬁers with fea tures from the training set and their accuracy was measured by comparing their predictions to the ground truth from the testing set. For this ﬁrst round of tests, no classiﬁcation val idation was used. This was to aid our understanding of how the classiﬁers would perform without any additional post processing. Fig. 4 shows the resulting confusion matrix for our Per Flow Random Forest Classiﬁer (Approach 2). For brevity, we show only one confusion matrix since the other classiﬁcation approaches yielded similar plots. Furthermore, in the confusion matrix itself, instead of showing app names, each of the 110 apps are assigned a unique number (0-109) on the axes. The y-axis shows the true apps responsible for the ﬂows, while the x-axis shows the predicted apps that were output from the classiﬁers. The cells in the confusion matrix show how well each ﬂow was classiﬁed, with a darker colour depicting more accurate classiﬁcation. Next we calculated precision, recall, and accuracy for our six classiﬁcation approaches. Where TP refers to the number of true positives, FP refers to the number of false Figure 4: Normalized confusion matrix showing actual classes vs. predicted classes for the Per Flow Random ForestClassiﬁer.  

---

 ## 翻译[10/16]：
 

表格3：显示超过1%阈值的40种统计特征得分的百分比。在训练过程结束时，分类器会进行序列化，这个过程称为 pickling。pickling 是 Python 提供的一个功能，它允许将分类器数据结构和对象状态转换成文件。实验的目的是了解我们能够多么准确地从网络捕获的交互流量中指纹识别并重新识别应用程序。对于这些测试，AppScanner 通过从110个应用程序中收集的交互流量进行训练。这些应用程序是从2015年7月谷歌应用商店排名前150的免费应用程序中随机选择的。（请参见附录中的表格9，了解用于测试 AppScanner 的应用程序列表。）我们选择排名最高的应用程序，因为我们相信这些应用程序代表了全球应用程序总安装量的很大部分。如果 AppScanner 在这些应用程序上表现良好，就说明 AppScanner 作为一个识别应用程序的框架在全球范围内是有用的。此外，我们使用免费应用程序，因为免费应用程序往往包含比付费应用程序更多的广告，因此会产生更多的广告流量。由于来自特定广告网络的广告流量往往是相似的，因此 AppScanner 在将广告流量分类为使用相同广告网络的应用程序组中的一个应用程序时会更加困难。的确，我们的结果证实了这一点。因此，我们认为在免费应用程序上测试 AppScanner 的结果是最差的性能数据。

在训练分类器之前，我们需要选择适当的识别最小流量长度的值。对于这个测试，我们选择了我们的按流随机森林分类器（方法2），并在保持最大流量长度阈值为无穷大的同时改变了最小流量长度阈值。图3显示了改变最小流量长度对分类准确度的影响。分类器准确度从1个数据包的流量长度急剧增加到7个数据包的流量长度，并在之后保持了稳定（或多或少）。这是可以理解的，因为较短的流量携带的信息较少，因此我们希望在分类较短的流量时分类器会制造更多的错误。7个数据包的流量长度是一个很好的最小流量长度选择，因为它是最短的“完整”流量的长度；即一个包含TCP握手（三个数据包）后跟HTTP请求、响应和确认（四个数据包）的流量。请注意，我们认为TCP会话终止数据包不属于最短完整流量的长度范围内。这是因为突发阈值通常会在TCP会话终止数据包之前发生，因此它们永远不会成为流量的一部分。因此，在其余测试中，选择了最小流量长度为7。当然，这可以根据任何其他特定需求进行轻松调整。其他分类方法产生的结果与不同最小流量长度对分类器准确度的影响相似，为了简洁起见，在此不做讨论。

使用最短流量长度为7和最大流量长度为260的随意交互流量被分为了75%/25%的训练/测试数据集。我们选择了最大流量长度为260，因为这是我们训练数据中观察到的最长流量的长度。根据典型的使用情况预计的最大流量长度可以轻松调整此值。我们使用训练集中的特征训练了分类器，并通过将其预测与测试集的基本事实进行比较来测量其准确性。对于这个第一轮测试，没有使用分类验证。这是为了帮助我们了解分类器在没有任何其他后处理的情况下的性能。图4显示了我们的按流随机森林分类器（方法2）的混淆矩阵结果。为了简洁起见，我们只展示了一个混淆矩阵，因为其他分类方法产生了相似的情况矩阵。此外，在混淆矩阵本身中，每个110个应用程序在轴上被分配了唯一的编号（0-109），而不是显示应用程序名称。y轴显示负责流程的真实应用程序，而x轴显示从分类器输出的预测应用程序。混淆矩阵中的单元格显示了每个流的分类情况，颜色越深，分类越准确。接下来，我们计算了六种分类方法的精确度、召回率和准确度。其中，“TP”表示真正例的数量，FP表示假正例的数量。

## 

---

 ## 原文[11/16]： 

 
 positives, FN refers to the number of false negatives, and TN refers to the number of true negatives: precision was calculated using the formula TP/(TP + FP), and recall was calculated using the formula TP/(TP + FN). For Approaches 1-4 (the multi-class classiﬁers), accuracy was calculated as the total number of correct classiﬁcations divided by the total number of classiﬁcations. Approaches 5-6 involved binary classiﬁers so accuracy was calculated as (TP + TN)/(TP + FP + TN + FN). The results are reported in Table 4. Without using classiﬁcation validation, AppScanner had best overall performance with Per App Random Forest Classiﬁers trained on statistical features from network ﬂows (Approach 6). These classiﬁers had an overall precision of 96.0%, recall of 82.5%, and accuracy of 99.8% for our test set of 110 apps. Our Per App Support Vector Classiﬁers (Approach 5) had comparable precision and accuracy, but a lower recall of 64.8%. Given that no classiﬁcation validation had been used with the results presented in Table 4, these are the worst case performance ﬁgures that can be expected from AppScanner using theseclassiﬁcation approaches.

 For the next round of tests, we wanted to measure the impact that increasing the number of classes had on clas siﬁcation accuracy for our multi-class classiﬁers (Approach 1-4). We started with a set size of 10 apps which were chosen randomly from our test set of 110 apps. The classi ﬁcation performance was measured. This test was repeated 50 times (with random sets of the same set size) and the results averaged. This entire process was repeated, each time increasing the app set size by 10, until we had the maximum set size of 110. The result of these tests are shown in Fig. 5. From the ﬁgure we can see that increasing the number of apps in the classiﬁers causes precision, recall, and overall accuracy of classiﬁcation to decrease. This is not TABLE 4: Table showing classiﬁer performance for the six classiﬁcation approaches: Per Flow SVC, Per Flow Random Forest Classiﬁer, Single Large SVC, Single Large Random Forest Classiﬁer, Per App SVC, and Per App Random ForestClassiﬁer.

 Figure 5: Impact of the number of apps trained in the classiﬁers on classiﬁer performance for the four multi-class classiﬁers. Error bars show 95% CI for the mean. unexpected, since the accuracy of a multi-class classiﬁer is a function of the number of classes that an unknown input can be matched to. What is important to note, however, is that as the number of classes is increased, the rate of decrease in classiﬁer performance decreases. Thus we expect classiﬁer performance to eventually level off and remain constant when the number of classes is signiﬁcantly increased. If one wanted to ﬁngerprint the universe of apps, they would use the Classiﬁer Per Flow Length strategy (Ap proach 1-2 in Section 4). This would ensure that no single classiﬁer would contain a very large number of apps, since not all apps generate ﬂows for each ﬂow length. For this rea son, we believe that scaling up AppScanner to identify the universe of apps is feasible. Such large-scale ‘appscanning’ would not be common, though, since we believe the typical application scenario would be to use AppScanner to target a certain subset of apps. For example, by ﬁngerprinting the Top 10,000 apps, one would have a realistic coverage of all the apps that would be seen (with a non-trivial likelihood) on a given network. In other cases, we expect AppScanner to be deployed to only identify very speciﬁc apps (such as apps allowed/disallowed by company policy), in which case the Single Classiﬁer Per App strategy (Approach 5-6in Section 4) would be used.

 Figure 6: Histogram of prediction probabilities for each classiﬁcation as outputted by the Single Large SVC.

 5.2. Using Classiﬁcation Validation to Improve Per formance 

To understand the utility of the classiﬁcation validation post-processing function (as detailed in Section 3.4), we looked at the conﬁdence that our multi-class classiﬁers reported with each of their classiﬁcations. Fig. 6 shows a his togram of the prediction probabilities reported by our worst performing classiﬁer (Single Large SVC) for the ≈ 33, 500 ﬂows that were in the testing set. The prediction probability had a mean μ = 0.18 with standard deviation σ = 0.14. For the vast majority of classiﬁcations, the classiﬁer was less than 20% certain about its decision. Indeed, we can see from the ﬁgure that the classiﬁer was only around 10-12%conﬁdent for a large number of choices.  

---

 ## 翻译[11/16]：
 

本文中的正例（TP）指真实正例被分类器正确识别的数量，假阴性（FN）指真实正例被分类器错误地识别成负例的数量，真阴性（TN）指真实负例被分类器正确识别的数量。通过公式TP /（TP + FP）计算准确率，通过公式TP /（TP + FN）计算召回率。对于方法1-4（多类分类器），准确率计算为总正确分类数除以总分类数。方法5-6涉及二进制分类器，因此准确率计算为（TP + TN）/（TP + FP + TN + FN）。结果见表4。在不使用分类验证的情况下，AppScanner使用来自网络流的统计特征训练的Per App随机森林分类器（方法6）具有最佳的整体性能。这些分类器在我们的110个测试应用程序集上具有总体精度为96.0％，召回率为82.5％，准确率为99.8％。我们的每应用支持向量分类器（方法5）具有可比的精度和准确率，但召回率较低，为64.8％。鉴于在表4中呈现结果时未使用分类验证，这些是AppScanner使用这些分类方法时可以预期的最差情况绩效数据。

对于下一轮测试，我们想衡量增加类别数量对多类分类器（方法1-4）分类准确性的影响。我们从110个测试应用程序集中随机选择了一组大小为10个的应用程序集开始。测量分类性能。我们重复这个测试50次（具有相同集合大小的随机集合），并平均结果。每次重复整个过程，每次增加10个应用程序集大小，直到我们拥有最大的110个应用程序集大小为止。这些测试的结果如图5所示。从图中可以看出，增加分类器中应用程序的数量会导致分类器的精度，召回率和总体分类准确性降低。然而，这并不出乎意料，因为多类分类器的准确率是未知输入可以匹配的类别数量的函数。然而，值得注意的是，随着类别数量的增加，分类器性能的下降率减慢。因此，当类别数量显着增加时，我们预计分类器性能最终会趋于稳定并保持恒定。如果想要对应用程序的宇宙进行指纹识别，则使用分类器Per Flow Length策略（第4节的方法1-2）。这将确保单个分类器不包含大量应用程序，因为并非所有应用程序都为每个流长度生成流。出于这个原因，我们认为将AppScanner扩展到识别应用程序的宇宙是可行的。然而，这样大规模的“appscanning”并不常见，因为我们认为典型的应用程序方案将是使用AppScanner针对某个应用程序的子集。例如，通过指纹识别前10000个应用程序，一个人可以实现涵盖所有应用程序的实际覆盖范围（具有非微不足道的可能性）并在给定网络上看到每个应用程序。在其他情况下，我们期望AppScanner仅用于识别非常具体的应用程序（例如公司政策允许/禁止的应用程序），这种情况下将使用单个分类器Per应用程序策略（第4节的方法5-6）。

为了了解分类验证后处理功能（如第3.4节所述）的效用，我们查看了我们的多类分类器报告的每个分类的置信度。图6显示了最劣性能分类器（Single Large SVC）报告的预测概率的直方图，用于测试集中的约33,500个流。预测概率的平均值为μ = 0.18，标准偏差为σ = 0.14。对于绝大多数分类，分类器对其决策不到20％的部分是不确定的。实际上，我们可以从图中看出，分类器仅对大量选择的约10-12％感到自信。

## 

---

 ## 原文[12/16]： 

 
 In the case where more than one apps had similar ﬂows, such as ad/analytics trafﬁc or querying similar APIs, it is understandable that the classiﬁers would not be very conﬁdent in their classiﬁcations. This is so, because the class boundaries would not be as distinct as in the case where all apps had perfectly unique trafﬁc. This suggests that classiﬁcation validation can be a useful strategy for improv ing classiﬁcation performance since we can set ‘minimum standards’ for what we will accept from the classiﬁer as a conﬁdent classiﬁcation. By using classiﬁcation validation, we can free AppScanner from the task of making a decision on ﬂows that are genuinely very ambiguous to the classiﬁer. Table 5 summarises the (sometimes) dramatic improve ment in classiﬁcation performance that we obtained by us ing classiﬁcation validation. In general, the Random Forest Classiﬁers outperformed the Support Vector Classiﬁers for our dataset, whether a Classiﬁer Per Flow Length or a Single Large Classiﬁer was used. The Random Forest Classiﬁers use aggregated decision trees which, in turn, reduce bias. Also, they are better able to handle noise since they are an ensemble learning method. The Support Vector Classiﬁers are not very conﬁdent about their predictions and indeed it can be seen that the percentage of ﬂows they were conﬁ dent enough to classify falls off sharply as the prediction probability threshold is increased. The overall winner is the Single Large Random Forest Classiﬁer (Approach 4) that used statistical features derived from ﬂows. We now detail the performance of these classiﬁcation approaches. Fig. 7a shows classiﬁer performance for our Per Flow Length Support Vector Classiﬁers (Approach 1). With no classiﬁcation validation in use, precision, recall, and accu Figure 7: Impact of prediction probability threshold on classiﬁer performance. racy was 77.1%, 71.9%, and 71.5%, respectively, with the classiﬁers making a judgement on all the unlabelled ﬂows. By setting the prediction probability threshold to a modest 0.5, precision, recall, and accuracy increased to 95.1%, 92.4%, and 95.0% respectively with the classiﬁers making judgements on just under a half (45.5%) of the unlabelled ﬂows. From the ﬁgure it can be seen that accuracy in excess of 99% (accuracy of 99.1%, precision of 97.2%, recall of 92.3%) can be achieved by setting the prediction probability threshold to 0.7. At a threshold of 0.7, however, AppScanner will only be conﬁdent enough to make a judgement on roughly a quarter (26.0%) of ﬂows. At higher thresholds, the number of ﬂows classiﬁed falls off sharply with negligibleimprovement in performance.

 Fig. 7b shows classiﬁer performance for our Per Flow Length Random Forest Classiﬁer (Approach 2). With no classiﬁcation validation in use, precision, recall, and accu racy was 84.4%, 83.1%, and 82.1% respectively. At a thresh old of 0.5, accuracy jumps to 94.7% and we can exceed 98% accuracy at a threshold of 0.7, while still classifying over 71% of ﬂows. Although the Per Flow Length Support Vector Classiﬁers have a higher peak accuracy, the percentage of ﬂows they can classify at higher thresholds makes them useful in only very speciﬁc circumstances. Fig. 7c shows classiﬁer performance for our Single Large Support Vector Classiﬁer (Approach 3). This is our worst performing classiﬁer. With no classiﬁcation validation in use, precision, recall, and accuracy was 51.3%, 60.2%, and 42.4% respectively. By tuning the prediction probability threshold, additional performance can be squeezed from this classiﬁer but it comes at the detriment of percentage of ﬂows classiﬁed. The amount of ﬂows classiﬁed falls off even more sharply than the same type of classiﬁer used in a Per Flow Length Classiﬁer approach (Approach 1). At a threshold of 0.5, accuracy was less than 90% and to achieve this, the classiﬁer could only classify 5.9% of ﬂows. Fig. 7d shows classiﬁer performance for our Single Large Random Forest Classiﬁer (Approach 4). This is our best performing classiﬁer. With no classiﬁcation validation in use, precision, recall, and accuracy was 89.5%, 85.9%, and 86.9% respectively. At a threshold of 0.7, all three of precision, recall, and accuracy exceeded 98%, and at a threshold of 0.9, precision, recall, and accuracy all exceeded 99.5%. This near perfect accuracy is achieved while still being able to classify roughly three-quarters of all ﬂowsthat were seen.

 5.3. Understanding Classiﬁcation Errors   

---

 ## 翻译[12/16]：
 

在某些应用程序具有类似流程（例如广告/分析流量或查询类似API）的情况下，可以理解分类器对它们的分类不太有信心。这是因为类边界不会像所有应用程序的流量都完全独特的情况下那样明显。这表明，分类验证可以是提高分类性能的有用策略，因为我们可以为分类器设定“最低标准”，以接受从分类器中获得的自信分类。通过使用分类验证，我们可以使AppScanner不再负责对分类器非常模糊的流量做决策。表5总结了我们使用分类验证获得的（有时很显着的）分类性能改进。总体而言，在我们的数据集中，无论是使用每个数据流长度的分类器还是单个大型分类器，随机森林分类器的表现都优于支持向量分类器。随机森林分类器使用聚合决策树，从而减少偏差。此外，它们更能够处理噪声，因为它们是一种集成学习方法。支持向量分类器对其预测的自信度不高，而且可以看到，随着预测概率阈值的增加，它们能够自信分类的数据流的百分比急剧下降。总体胜利者是使用从数据流中衍生的统计功能的单个大型随机森林分类器（方法4）。现在，我们详细介绍这些分类方法的性能。图7a显示了我们的Per Flow Length支持向量分类器（方法1）的分类器性能。在没有使用分类验证的情况下，精度、召回率和准确率分别为77.1％、71.9％和71.5％，分类器对所有未标记的数据流进行判断。通过将预测概率阈值设为适度的0.5，精度、召回率和准确率分别增加到95.1％、92.4％和95.0％，而分类器对未标记的数据流进行判断不到一半（45.5％）。从图中可以看出，将预测概率阈值设置为0.7可以实现超过99％的准确性（准确性为99.1％，精度为97.2％，召回率为92.3％）。然而，在0.7的阈值下，AppScanner只有对大约四分之一（26.0％）的数据流进行判断的充足自信。在更高的阈值下，分类的数据流数量急剧下降，而性能几乎没有提高。图7b显示了我们Per Flow Length随机森林分类器（方法2）的分类器性能。在没有使用分类验证的情况下，精度、召回率和准确率分别为84.4％、83.1％和82.1％。在0.5的阈值下，准确率跃升至94.7％，而在0.7的阈值下，我们可以超过98％的准确率，同时仍对71％以上的数据流进行分类。虽然Per Flow Length支持向量分类器具有更高的峰值准确性，但它们在更高阈值下可以分类的数据流比较特定。图7c显示了我们的Single Large支持向量分类器（方法3）的分类器性能。这是我们表现最差的分类器。在没有使用分类验证的情况下，精度、召回率和准确率分别为51.3％、60.2％和42.4％。通过调整预测概率阈值，可以从该分类器中挤出更多性能，但会减少分类的数据流的百分比。分类的数据流数量下降得比在每个数据流长度的分类器方法（方法1）中使用相同类型的分类器还要急剧。在0.5的阈值下，准确率低于90％，为了实现这一点，分类器只能分类5.9％的数据流。图7d显示了我们的Single Large随机森林分类器（方法4）的分类器性能。这是我们表现最好的分类器。在没有使用分类验证的情况下，精度、召回率和准确率分别为89.5％、85.9％和86.9％。在0.7的阈值下，精度、召回率和准确率均超过98％，在0.9的阈值下，精度、召回率和准确率均超过99.5％。能够对观察到的大约四分之三的所有数据流进行分类，实现近乎完美的准确性。

## 

---

 ## 原文[13/16]： 

 
Some classiﬁcation approaches performed better than others both in terms of precision/recall/accuracy as well as percentage of ﬂows classiﬁed when using classiﬁcation val idation. Some of the apps themselves also performed better than others when being classiﬁed by AppScanner. We expect that the better performing apps are those that have trafﬁc ﬂows that are very distinct from the ﬂows of other apps. To test this hypothesis, we analysed our Per Flow Random Forest Classiﬁer (Approach 2), the classiﬁer from the group that had overall performance somewhere in the middle (not the best and not the worst). Table 6 shows the apps that were most accurately classiﬁed by this classiﬁer (without using classiﬁcation validation). We removed classiﬁcation validation for this step to get a fuller idea of the types of ﬂows that were being classiﬁed incorrectly. The package air.uk.co.bbc.android.mediaplayer was perfectly classiﬁed TABLE 5: Table summarising multi-class classiﬁer perfor mance when classiﬁcation validation is used. TABLE 6: Best 10 Apps for classiﬁcation by AppScanner. in all cases with another 15 apps exceeding a classiﬁcation accuracy of 90%. Other apps performed much worse as shown in Table 7. None of the ﬂows from the package com.google.android.apps.plus were classiﬁed correctly by AppScanner when not using classiﬁcation validation. An other 13 apps from our test set of 110 apps performed below the 50% mark with this setting. These apps seem to generate ﬂows are harder to classify and thus produce more false positive and false negative results. To understand if this was the case, we did an in-depth analysis of the incorrectly classiﬁed ﬂows to gain additional insight. With classiﬁcation validation still removed, we performed another set of tests where AppScanner would make its best guess at what app a ﬂow belonged to. We did this analysis using classiﬁcation Approach 1; another approach where performance was in the middle (not the best and not the worst). We collected the ≈ 10, 000 ﬂows (of ≈ 33, 500) that were classiﬁed in correctly (using this classiﬁcation approach) and performed manual/semi-automated analysis on them by destination IPaddress.

 The ≈ 10, 000 incorrectly classiﬁed ﬂows were going to some 1,467 unique destination IP addresses. It is interesting to note that the Top 25 of these IP addresses accounted for more than 30% of the incorrectly classiﬁed ﬂows. For brevity, we report on the Top 10 destinations (for incorrectly TABLE 7: Worst 10 Apps for classiﬁcation by AppScanner. TABLE 8: Top 10 destinations for incorrectly labelled ﬂows, number of ﬂows going to these destinations, number of different apps sending these ﬂows, and the type of serviceat each destination.

 classiﬁed ﬂows) in Table 8. The table shows the domain names, the amount of incorrectly labelled ﬂows going to each domain, the number of apps sending ﬂows to each domain, and the type of service running at that domain. Note that the type of service running at a domain was inferred by manually doing research on the domain in the form of WHOIS queries, visiting the domain, analysing the subdomain etc. and thus may not be perfectly accurate inall cases.

 According to Table 8, with the exception of two do mains, all domains in our Top 10 ‘worst classiﬁcation do mains’ list received trafﬁc from more than one app. The re mainder of these ‘multi-app’ domains served either standard developer APIs or advertisement/analytics resources. This supports our hypothesis that similar ﬂows were indeed being sent by more than one apps as a result of them contacting the same standard web services. In this case, there is not much that can be done to assist AppScanner to differentiate the exact source of these network ﬂows without leveraging additional features. However, classiﬁcation accuracy could be improved if AppScanner were allowed to be more general and label a ﬂow as being advertisement/analytics/standard API trafﬁc instead of naming a speciﬁc app.

 6. Discussion and Future Work 

AppScanner is the implementation of a novel method ology that leverages machine learning and trafﬁc analysis to automatically ﬁngerprint and identify smartphone apps. The smartphone landscape offers unique challenges to trafﬁc analysis, such as less available features and the need for automation and high-scalability. Our classiﬁcation frame work based on ﬂows offers novel insights. We explore three general classiﬁcation strategies (i.e. classiﬁer per ﬂow length, single classiﬁer with all apps, and single classiﬁer per app) and explore and enumerate the trade-offs of each strategy in terms of time taken to train classiﬁer, size of resulting classiﬁer, and classiﬁcation performance. Our framework is able to very accurately identify apps from their network trafﬁc but it also has some limitations. We discuss these limitations in Section 6.1, we compare AppScanner to the state of the art in Section 6.2, and talkabout future work in Section 6.3.

 6.1. Limitations   

---

 ## 翻译[13/16]：
 

在使用分类验证时，有些分类方法在精度/召回率/准确率和分类流百分比方面表现比其他方法好。在被AppScanner分类时，一些应用程序比其他应用程序的表现也更好。我们预计表现更好的应用程序是具有非常不同于其他应用程序流量的应用程序。为了检验这个假设，我们分析了Per Flow Random Forest分类器（方法2），该分类器是综合表现介于最佳和最差之间的小组的分类器。表6显示了该分类器在没有使用分类验证的情况下最准确分类的应用程序。我们为此步骤删除了分类验证，以更全面地了解被错误分类的流类型。空气包.uk.co.bbc.android.mediaplayer在所有情况下都被完美地分类，其余15个应用程序的分类精度超过90％。如表7所示，其他应用程序的性能要差得多。当不使用分类验证时，来自com.google.android.apps.plus包的任何流都没有被AppScanner正确分类。我们的110个测试应用程序集中的另外13个应用程序在此设置下表现低于50％。这些应用程序似乎产生难以分类的流，从而产生更多的误报和漏报结果。为了了解这是否属实，我们对错误分类的流进行了深入分析以获得更多的洞见。仍然删除分类验证，我们使用分类方法1进行了另一组测试，其中性能介于最佳和最差之间。我们通过目标IP地址对≈10,000个分类不正确的流进行了手动/半自动分析。≈10,000个错误分类的流分别到达1,467个唯一的目标IP地址。有趣的是，其中前25个IP地址占错误分类的流量的30％以上。为了简洁起见，我们在表格8中报道了前10个目的地的情况。该表显示了每个域名的不正确标记的流量量，发送流到每个域名的应用程序数以及在该域中运行的服务类型。根据表8，除两个域名外，我们最糟糕的10个分类域名列表中的所有域名都接收来自多个应用程序的流量。这些'multi-app'域名的其余部分提供标准的开发人员API或广告/分析资源。这支持我们的假设，即因为它们联系相同的标准web服务而产生相似的流，因此确实会由多个应用程序发送相似的流。在这种情况下，除了利用更多特征之外，没有什么可以帮助AppScanner区分这些网络流的确切来源。但是，如果允许AppScanner更加通用地将流标记为广告/分析/标准API流量而不是命名特定的应用程序，则可以提高分类准确性。

# 6. 探讨与未来工作

AppScanner是利用机器学习和流量分析自动分类指纹识别智能手机应用的新方法学。智能手机领域在流量分析方面提供了独特的挑战，例如可用功能较少以及需要自动化和高扩展性。我们基于流的分类框架提供了新颖的见解。我们探索了三种常规分类策略（即每个流长度的分类器，带有所有应用程序的单个分类器以及每个应用程序的单个分类器），并在训练分类器所需的时间，所得到的分类器的大小以及分类表现方面探索并列举了妥协。我们的框架能够非常准确地识别应用程序的网络流量，但它也存在一些限制。我们在6.1节中讨论了这些限制，并在6.2节中将AppScanner与现有技术进行了比较，并在6.3节中讨论未来的工作。

## 

---

 ## 原文[14/16]： 

 
Table 7 shows that AppScanner was much worse at identifying some apps such as Temple Run, Pedometer, MeetUp, Inbox by Gmail, and Google+. This, we think, is as a result of these apps having very generic ﬂows of trafﬁc. This hypothesis is supported by Table 8, where we see that the most incorrectly labelled ﬂows were from multiple apps going to similar destinations. The simple fact is that ambiguous ﬂows are harder to classify and AppScanner (or any other system) would not be able to reliably differentiate between these ﬂows without leveraging additional features. AppScanner was built with a single device that generated the training and testing ﬂows. It is possible that apps may behave differently on different devices or different versions of Android. It is also possible that different ﬂavours of TCP on different devices may cause our classiﬁers to misclassify if they were trained using network traces from a differ ent device. We plan to test this by generating ﬂows from apps using various Android emulators running on virtualmachines.

 6.2. Comparison with website ﬁngerprinting meth ods 

Since the domain of this paper is smartphone app ﬁn gerprinting, and the closest related work we identiﬁed in Section 2 focuses mainly on website ﬁngerprinting, a di rect comparison between AppScanner and the related work cannot be made. However, we validate the necessity and utility of AppScanner by showing how the existing website trafﬁc analysis techniques in the literature (for which there exists ground truth) perform below par when classifying the smartphone app trafﬁc from our dataset. The results of ourcomparison are shown in Fig. 8.

 The ﬁrst group of approaches considered for the com parison are the ones proposed by Liberatore et al. in [11]: a classiﬁer leveraging the Jaccard similarity metric (i.e., Liberatore Jaccard) and another leveraging a Naive Bayes classiﬁer (i.e., Liberatore NB). Among these two classiﬁers, Liberatore NB achieves the best accuracy with 50.8%. The second group of approaches were presented by Herrmann et al. in [12]. The difference with the proposals in this group is that transformations are applied to the dataset: Figure 8: AppScanner’s accuracy compared to existing ap proaches from the literature. We use pt to denote the predic tion probability threshold used for classiﬁcation validation.RF means Random Forest Classiﬁer.

 no transformation (i.e., Herrmann Pure), Term Frequency transformation (i.e., Herrmann TF), and Cosine Normaliza tion applied after a TF transformation (i.e., Herrmann Cos). The best performance is 50.2% accuracy, achieved by the TF transformation without the Cosine Normalization, i.e., Herrmann TF. Finally, the method proposed by Panchenko et al. in [13] performed best with an accuracy of 64.5%. As we can see from Fig. 8, this is the approach with performance closest to ours. However, ﬁve out of six of our classiﬁers outperform it, with our two best approaches outperforming it by some 35% accuracy. Our worst four approaches, when using classiﬁcation validation (with a modest prediction probability threshold of 0.5) outperformPanchenko et al. by 25%-30% accuracy.

 6.3. Future Work 

For future work, we will examine ways of grouping ﬂows to more reliably determine the originating app. For example, three ﬂows may be ambiguous when analysed sep arately, but when assessed as a group, they may match a par ticular app that always sends three of these ﬂows together. We will also look at other approaches for identifying apps, such as active network probing, which can be used to elicit further identifying network trafﬁc from apps. We intend to use different modelling tools, such as Hidden Markov Models and ﬁnite state machines, for app classiﬁcation. We also plan to improve classiﬁcation accuracy by identifying and using other features from ﬂows, such as packet inter arrival time. Other readily available information such as whether a ﬂow always occurs within a burst with multiple ﬂows or whether it contains HTTPS/TLS packets can also be leveraged to improve accuracy. Finally, we plan to examine the extent to which app ﬁngerprinting can be done at the MAC layer in the presence of MAC layer encryption.

 7. Conclusion 

In this paper, we presented AppScanner, a framework implementing a novel methodology for the automatic ﬁn gerprinting and real-time identiﬁcation of smartphone apps from their encrypted network trafﬁc. Our evaluation shows that apps can indeed be identiﬁed with over 99% accuracy even in the presence of encrypted trafﬁc streams such as HTTPS/TLS. We validated that multi-class classiﬁers can be used to ﬁngerprint and identify a wide variety of apps in a single classiﬁer. We also showed that binary classiﬁers can also be used to obtain very high precision and overall accuracy in the case where only certain apps are of interest. Undoubtedly, smartphone usage will continue to increase as app developers continue to provide new apps to consumers to satisfy their insatiable appetites. As a result, more and more actors will become interested in ﬁngerprinting and identifying these apps for both benevolent and malevolent reasons. By continuing research in this area we hope to gain a better understanding of the privacy and security risks that end users currently face. In this way, we can continue on the path of helping to preserve privacy and security now andinto the future.

 Acknowledgement   

---

 ## 翻译[14/16]：
 

表格7显示，AppScanner在识别Temple Run、Pedometer、MeetUp、Inbox by Gmail和Google+等应用程序方面表现更差。我们认为这是由于这些应用具有非常普遍的流量流程所导致的。通过表格8，我们得到了支持这个假设的证据，其中我们看到大多数分类错误的流量来自于多个应用程序到达相似目的地。事实是，不确定性的流量更难以分类，而且AppScanner（或任何其他系统）在没有利用其他特征的情况下将无法可靠地区分这些流量。AppScanner是使用一个设备生成的训练和测试流量构建的。可能存在不同设备或不同版本的Android上应用的行为可能不同。它还可能导致不同设备上不同TCP版本的误分类，如果使用从不同设备的网络跟踪生成的训练数据进行训练的分类器。我们计划通过使用在虚拟机上运行的各种Android模拟器生成应用程序的流量来测试这个问题。

# 6.2与网站指纹技术的比较

由于本文的领域是智能手机应用指纹识别，而在第2节中发现的最相关的工作主要关注网站指纹识别，因此不能直接比较AppScanner和相关工作。然而，通过展示文献中现有的网站流量分析技术（已有实测对照）在对我们的数据集中的智能手机应用程序流量进行分类时的性能差距，我们验证了AppScanner的必要性和实用性。我们的比较结果如图8所示。

考虑到比较的第一组方法是由Liberatore等人在[11]中提出的方法：使用Jaccard相似性度量的分类器（即Liberatore Jaccard）和使用朴素贝叶斯分类器的另一种方法（即Liberatore NB）。 在这两个分类器中，Liberatore NB的准确度最高，为50.8％。第二组方法是由Herrmann等人在[12]中提出的。与本组中的建议的不同之处在于，对数据集应用了转换：没有任何转换（即Herrmann Pure），使用词项频率转换（即Herrmann TF），以及进行词项频率转换后应用余弦归一化（即 Herrmann Cos）。最佳性能是由TF转换（即Herrmann TF）而没有余弦归一化实现的50.2％准确度。最后，Panchenko等人在[13]中提出的方法表现最佳，准确率为64.5％。正如我们所看到的在图8中，这是与我们最接近的性能方法。然而，使用我们最差的四种方法（使用分类验证，采用较小的预测概率阈值0.5）的结果比Panchenko的结果提升了25％-30％。

# 6.3未来工作

作为未来工作，我们将研究将流量分组的方法，以更可靠地确定原始应用程序。例如，当分别分析三个流时，它们可能是不确定的，但当作为一组进行评估时，它们可能与特定应用匹配，该应用程序总是发送这三个流之一。我们还将研究其他用于识别应用的方法，例如主动网络探测，该方法可以用于从应用程序中引出进一步的网络流量信息。我们打算使用不同的建模工具，如隐马尔可夫模型和有限状态机进行应用程序分类。我们还计划通过识别和使用来自流量的其他特征，例如包间隔时间，来提高分类准确度。其他可用信息，例如一个流始终在包含多个流的突发中到达，或者它是否包含HTTPS/TLS包，也可以用于提高准确度。最后，我们计划检查在MAC层中是否存在MAC层加密的情况下可以完成应用程序指纹识别的程度。

# 7. 结论

本文介绍了AppScanner，这是一种实现新型方法的框架，用于自动地指纹识别和实时识别智能手机应用程序中的加密网络流量。我们的评估表明，即使在存在HTTPS/TLS等加密流量的情况下，也可以以超过99％的准确率识别应用程序。我们验证了可以使用多类分类器在单一分类器中进行指纹识别和标识各种应用程序。在只涉及特定应用程序的情况下，我们还展示了可以使用二元分类器以获得非常高的精度和整体准确度。毫无疑问，随着应用程序开发人员继续提供新的应用程序来满足消费者的无限欲望，智能手机的使用将继续增加。因此，越来越多的参与者将对指纹识别和识别这些应用程序感兴趣，无论是出于善良还是恶意的目的。通过继续在这个领域进行研究，我们希望对当前用户面临的隐私和安全风险有更好的了解。通过这种方式，我们可以继续努力保护隐私和安全，并将其延续到未来。

# 致谢

## 

---

 ## 原文[15/16]： 

 
Vincent F. Taylor is supported by a Rhodes Scholarship and the UK EPSRC. Mauro Conti is supported by a Marie Curie Fellowship (PCIG11-GA-2012-321980). This work is also supported by the projects EU TagItSmart! (H2020 ICT30-2015-688061), EU-India REACH (ICI+/2014/342 896), Italian PRIN TENACE (20103P34XC), and University of Padua PRAT-2013 on Malware Detection.

 Appendix 

TABLE 9: List of apps in the AppScanner testing set. App details were obtained from the Google Play Store [25].  

---

 ## 翻译[15/16]：
 

Vincent F. Taylor由Rhodes奖学金和英国EPSRC资助，Mauro Conti由Marie Curie Fellowship(PCIG11-GA-2012-321980)资助。该工作还得到了EU TagItSmart!(H2020 ICT30-2015-688061)、EU-India REACH(ICI+/2014/342 896)、意大利PRIN TENACE(20103P34XC)和University of Padua PRAT-2013关于恶意软件检测的支持。
 
# 附录

表9：AppScanner测试集中的应用程序列表。应用程序的详细信息来源于Google Play Store[25]。

