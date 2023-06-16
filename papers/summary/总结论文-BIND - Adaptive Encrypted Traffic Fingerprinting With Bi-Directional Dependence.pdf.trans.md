# BIND - Adaptive Encrypted Traffic Fingerprinting With Bi-Directional Dependence 分析报告
## 一、论文概况

---



### 标题
Adaptive Encrypted Trafﬁc Fingerprinting With Bi-Directional Dependence

### 收录会议或期刊
Unknown

### 作者
Khaled Al-Naami, Swarup Chandra, Ahmad Mustafa, Latifur Khan, Zhiqiang Lin, Kevin Hamlen, and Bhavani Thuraisingham

### 摘要
Recently, network trafﬁc analysis has been increasingly used in various applications including security, targeted advertisements, and network management. However, data encryption performed on network trafﬁc poses a challenge to these analysis techniques. In this paper, we present a novel method to extract characteristics from encrypted trafﬁc by utilizing data dependencies that occur over sequential transmissions of network packets. Furthermore, we explore the temporal nature of encrypted trafﬁc and introduce an adaptive model that considers changes in data content over time. We evaluate our analysis on two packet encrypted applications: website ﬁngerprinting and mobile application (app) ﬁngerprinting. Our evaluation shows how the proposed approach outperforms previous works especially in the open-world scenario and when defense mechanisms are considered.

### 编号
1

### 作者邮箱
{khaled.al-naami, swarup.chandra, ahmad.mustafa, lkhan, zhiqiang.lin, hamlen, bhavani.thuraisingham}@utdallas.edu

### 中文翻译摘要
最近，网络流量分析在各种应用中越来越广泛地使用，包括安全、定向广告和网络管理。然而，对网络流量执行的数据加密对这些分析技术构成了挑战。本文提出了一种新的方法，利用网络数据包的顺序传输中发生的数据依赖性从加密的流量中提取特征。此外，我们探讨了加密流量的时间性质，并引入了一个自适应模型，考虑到数据内容随时间的变化。我们在两个加密应用上评估了我们的分析：网站指纹识别和移动应用程序（app）指纹识别。我们的评估显示了所提出的方法在特别是在开放世界场景和考虑到防御机制时如何优于以前的工作。

---



## 二、论文翻译



## 

---

 ## 原文[0/13]： 

 

 Khaled Al-Naami, Swarup Chandra, Ahmad Mustafa, Latifur Khan, Zhiqiang Lin, Kevin Hamlen, and Bhavani Thuraisingham

 {khaled.al-naami, swarup.chandra, ahmad.mustafa, lkhan, zhiqiang.lin, hamlen, bhavani.thuraisingham}@utdallas.edu Abstract 

Recently, network trafﬁc analysis has been increasingly used in various applications including security, targeted advertisements, and network management. However, data encryption performed on network trafﬁc poses a challenge to these analysis techniques. In this paper, we present a novel method to extract characteristics from encrypted trafﬁc by 

utilizing data dependencies that occur over sequential transmissions of network packets. Furthermore, we explore the temporal nature of in data content over time. We evaluate our analysis on two packet 

encrypted applications: website ﬁngerprinting and mobile application (app) ﬁngerprinting. Our evaluation shows how the proposed approach outperforms previous works especially in the open-world scenario and when defense mechanisms are considered.

 1. INTRODUCTION 

With a tremendous growth in the number of Internet users over the past decade, network trafﬁc analysis has gained signiﬁcant interest in both academia and industry. Applications such as personalized for tracking online activities of users [24]. For example, by tracking the websites accessed by a particular user, related products may be 

advertised. Unfortunately, online users have fallen victim to adversaries who use such tracking mechanisms for malicious activities by passively monitoring network trafﬁc. As a result, encryption technologies 

such as SSL/TLS are used extensively to hide data in network trafﬁc from unauthorized access. In addition to data encryption, end-node adversaries using technologies such as Tor [14], to anonymize the user. Recent studies [7,36] on trafﬁc analysis have focused on identifying characteristic patterns in network trafﬁc that reveal the behavior of an end-node, thereby de-anonymizing the network. Essentially, pattern recognition techniques are employed over features extracted from encrypted network trafﬁc passively captured at the user’s end. This behavior identiﬁcation process of an end-node (i.e. either a service 

accessed by the user, or an application at the user’s end involved in the network trafﬁc) is called Trafﬁc Fingerprinting. Figure 1: Illustration of website and app ﬁngerprinting 

In this paper, we focus on the following two applications (illustrated in Figure 1) whose primary goal is to perform trafﬁc ﬁngerprinting to identify an end-node generating encrypted trafﬁc. Here, a man-in 

the-middle (i.e., network administrator, ISP, government agency, etc) captures encrypted network trafﬁc passively at the user’s end. Website Fingerprinting. This application involves identifying the webpage (end-node) accessed by a user who actively hides online activities using an anonymity network such as Tor. Knowledge of the user’s online activities may be useful in applications such as targeted advertisements, tracking terrorist activities, checking for DRM violations, etc. On the contrary, it violates the user’s online 

privacy. Destination IP addresses obtained from encrypted trafﬁc in this setting cannot be used for webpage identiﬁcation since they would be encapsulated by the encryption scheme. Fingerprinting over such encrypted data for identiﬁcation of webpage (or website) is widely known as Website Fingerprinting [25]. We denote this as WFIN. App Fingerprinting. Unlike websites, smartphone apps access the their operation. Examples of such services include advertisements, 3rd party libraries, and other API-based services. Applications, such as ad relevance, network bandwidth management, and app recommendations, may require the knowledge of apps running on a particular device in order to improve user experience. On the other hand, an adversarial view of such knowledge may lead to initiation of targeted attacks [39] involving known vulnerabilities in apps. While apps do not hide the destination IP addresses, they may access multiple overlapping destinations. For example, two apps may access the same 3rd-party middle observing network trafﬁc, identifying the two apps on the same device is hard when relying only on the IP addresses. However, the We call the identiﬁcation of apps on a device, using their encrypted network trafﬁc patterns, App Fingerprinting, denoted by AFIN.

 177 

A fundamental challenge in performing trafﬁc ﬁngerprinting over 

encrypted data is the identiﬁcation of characteristic features, which are consists of network packets that carry application data along with other control messages depending on the communication protocol. In general, a protocol such as TCP limits the size of each packet. Moreover, each packet incurs a ﬁnite transmission time depending on the network path followed from its source to its destination. When a man-in-the-middle passively captures a sequence of packets ﬂowing at the user’s end, the packet size, time-stamp, and direction can be observed to form a set of one must consider a sequence of network packets in the captured trafﬁc generated during a communication session involving the end-node under investigation. We call this sequence of packets a trace. 

Over time, the captured network trafﬁc may contain multiple traces associated with a set of end-nodes with different sessions initiated by the same user. In this setting, feature extraction is performed over each trace by combining features of each of its packets in a suitable 

manner [6,7,21,25,27,36]. Most existing techniques combine features by assuming independence between subsequent transmissions [6,27]. Therefore, relationship between packets in a TCP session, occurring downlinks from server to user), are ignored. A relationship between these packets may exist due to control messages resulting from thecurrent data transmission.  

---

 ## 翻译[0/13]：
 

Khaled Al-Naami、Swarup Chandra、Ahmad Mustafa、Latifur Khan、Zhiqiang Lin、Kevin Hamlen和Bhavani Thuraisingham

{khaled.al-naami，swarup.chandra，ahmad.mustafa，lkhan，zhiqiang.lin，hamlen，bhavani.thuraisingham}@utdallas.edu

摘要 

最近，网络流量分析已经在包括安全、定向广告和网络管理等各种应用中被广泛使用。然而，对网络流量进行的数据加密给这些分析技术提出了挑战。本文提出了一种从加密流量中提取特征的新方法，该方法利用了网络数据包顺序传输时发生的数据依赖关系。此外，我们探讨了数据内容随时间的暂时性。我们通过两个Packet加密应用程序（网站指纹识别和移动应用程序（APP）指纹识别）对我们的分析进行了评估。我们的评估展示了该方法在特别是在开放环境和考虑防御机制时，优于以前的工作。

1. 引言 

在过去的十年中，随着互联网用户数量的大幅增长，网络流量分析已经引起了学术界和工业界的重视。个性化的定向广告等应用程序可用于跟踪用户的在线活动 [24]。例如，通过跟踪特定用户访问的网站，可以进行相关产品的广告推广。不幸的是，在线用户已经成为利用这种跟踪机制进行恶意活动的对手，通过被动监视网络流量。因此，加密技术（如SSL/TLS）广泛用于隐藏来自未经授权的人对网络流量中的数据的访问。除了数据加密之外，终端节点对使用Tor等技术的拥护者进行匿名进行匿名化。最近的流量分析研究[7,36] 集中于识别网络流量中反映终端节点行为的特征模式，从而去匿名化网络。根据以往的研究，通过在用户端被动捕获的从加密网络流量提取的特征上应用模式识别技术，可以对终端节点（即用户访问的服务或用户端参与网络流量的应用程序）进行行为识别处理，这就是流量指纹识别。在本文中，我们重点关注以下两个应用程序（如图1所示），其主要目标是执行流量指纹识别以识别生成加密流量的终端节点。在这种情况下，中间人（即，网络管理员，ISP，政府机构等)在用户端被动捕获加密网络流量。网站指纹识别。该应用程序涉及识别使用匿名网络（如Tor）主动隐藏在线活动的用户访问的网页（终端节点）。了解用户的在线活动对于定向广告、跟踪恐怖活动、检查DRM侵犯等应用程序可能是有用的。相反，它会侵犯用户的在线隐私。在此设置中，无法使用从加密流量中获得的目标IP地址对网页进行识别，因为它们将被加密方案所封装。通过加密数据进行网页识别的指纹识别广泛被称为网站指纹识别[25]。 我们将其称为WFIN。应用程序指纹识别。与网站不同，智能手机应用程序访问其操作。这些服务的示例包括广告、第三方库和其他基于API的服务。针对诸如广告相关性、网络带宽管理和应用程序推荐等方面的应用程序，可能需要了解在特定设备上运行的应用程序，以改善用户体验。另一方面，这种知识的对立视图可能会导致利用应用程序中已知漏洞的有针对性的攻击 [39]。虽然应用程序不隐藏目标IP地址，但它们可能会访问多个重叠的目标。例如，两个应用程序可能会访问同一个第三方中间人，当仅依赖IP地址时，很难在观察网络流量时识别这两个应用程序。然而，在它们的加密网络流量模式下，我们称其为应用程序指纹识别，标记为AFIN。

在使用加密数据进行流量指纹识别时，一个根本性的挑战是识别特征，这些特征包含传输应用程序数据以及依赖于通信协议的其他控制消息的网络数据包。通常，如TCP这样的协议限制每个分组的大小。此外，每个数据包会产生一个有限的传输时间，这取决于从其源到其目的地所遵循的网络路径。当中间人被动地捕获用户端流动的一系列数据包时，可以观察到数据包的大小、时间戳和方向，以形成一组数据包，称为数据包跟踪（trace）。随着时间的推移，捕获的网络流量可能包含与由同一用户发起的不同会话相关联的多个跟踪。在这种情况下，每个跟踪上执行特征提取，方法是以适当的方式组合每个跟踪中的每个数据包的特征 [6,7,21,25,27,36]。大多数现有技术通过假设不同数据传输之间相互独立的方式来组合特征[6,27]。因此，忽略了TCP会话中数据包之间的关系（在从服务器到用户的下行链接中发生），这些数据包之间可能存在由当前数据传输引发的控制消息所导致的关系。

## 

---

 ## 原文[1/13]： 

 
 Another major challenge in trafﬁc ﬁngerprinting is the changes of behavioral patterns in network trafﬁc over time, due to changes in the end-node content. While trafﬁc ﬁngerprinting can be seen as a continuous process with a man-in-the-middle observing network trafﬁc perpetually, a classiﬁcation model trained initially captures 

patterns in network trafﬁc available at that particular time. However, trafﬁc patterns may evolve over time, changing their distinguishing 

characteristics. Since these changes are not reﬂected in the classiﬁer, its performance degrades while classifying newer data. A recent study in WFIN observed this temporal behavior [23]. Yet, this remains an open challenge. Dependence), a new set of features from encrypted network trafﬁc, that incorporates feature relationships between consecutive sets of packets independent features to enrich discriminating factors of end-nodes during pattern recognition. Furthermore, we propose a technique 

for adapting the classiﬁer to temporal changes in data patterns while ﬁngerprinting over a long period of time. Our approach continuously monitors the classiﬁer performance on the training data. When the 

accuracy drops below a predeﬁned threshold, we replace the classiﬁer with another one trained on the latest data. We call this ADABIND (ADAptive ﬁngerprinting with BI-directioNal Dependence). Thesummary of our contributions is as follows.

 • We propose a new feature extraction method, called BIND, 

for ﬁngerprinting encrypted trafﬁc to identify an end-node. In 

particular, we consider relationships among sequences of packets in opposite directions. 

• We propose a method, called ADABIND, in which the machine learning classiﬁer adapts to the changes in behavioral patterns that occur when ﬁngerprinting over a long period of time. We 

continuously monitor classiﬁer performance, and re-train it in an online fashion. in existing studies. Moreover, we use a variety of datasets for both WFIN and AFIN while employing defense mechanisms to show the effectiveness of the proposed approaches especially in the open-world settings. relevant background information and related studies in WFIN and 

AFIN. We present BIND and ADABIND in Section 3. The empirical evaluation including datasets, experiments, and results are detailed in Section 4. Finally, we discuss certain limitations and future work inSection 5 and conclude the paper in Section 6.

 2. BACKGROUND 

In this section, we present relevant existing studies in trafﬁc analysis, particularly in WFIN and AFIN.

 2.1 Website Fingerprinting 

The online activity of a user accessing websites can be hidden using anonymity networks such as Tor [14]. Tor provides a low 

latency encrypted connectivity to the Internet, while anonymizing the connections via a process called pipeline randomization. A circuit of three relay nodes is formed within the Tor network, composed of an entry node, an exit node, and a randomly selected relay node. Circuit connections are reestablished approximately after every 10 minutes of usage [2]. Fingerprinting under this setting is hard due to Nevertheless, this challenging problem of WFIN has gained popularity in the research community with numerous studies [6,7,21,25,27,36] proposing techniques to perform ﬁngerprinting, and also to defend 

against it. The inductive assumption is that each website has a unique pattern in which data is transmitted from its server to the user’s browser. Moreover, each website content is unique. Using this assumption, the website ﬁngerprinting scenario, generally perceived as an attack against user’s privacy, employs a statistical model to predict the website name associated with a given trace. Whereas, a defense mechanism explores methodologies to reduce the effectiveness of such models capable ofperforming an attack.

 2.1.1 Attack 

The primary form of attack is to train a classiﬁer using traces 

collected from different websites, where each trace is represented as a set of independent features. Information present in network packets associated with each trace is summarized to form a histogram feature vector, where the features include packet length (size) and direction (as used in [25]). In addition, Panchenko et al. [28] introduced a set of features extracted from a combination of packets known as 

Size Markers or Bursts. A burst is a sequence of consecutive packets transmitted along the same direction (uplink or downlink). Features 

such as burst sizes are computed by summing the length of each packet within a burst. These, along with other features such as unique packet sizes, HTML markers, and percentage of incoming and outgoing 

packets, form the feature vector for a trace. Dyer et al. [17] also used bandwidth and website upload time as features.   

---

 ## 翻译[1/13]：
 

在流量指纹技术中的另一个主要挑战是由于终端节点内容的变化而导致的网络流量行为模式随时间的变化。虽然流量指纹可以被看作是一个连续的过程，中间人永久观察网络流量，但最初训练的分类模型捕捉到的是那个特定时段网络流量中可用的模式。然而，流量模式可能随时间演变，改变它们的区分特征。由于这些变化没有反映在分类器中，它的性能在对新数据进行分类时会下降。WFIN的一项最近研究观察到了这种暂态行为[23]。然而，这仍然是一个悬而未决的问题。我们提出了一种新的加密网络流量特征提取方法，称为BIND，它包括连续数据包集之间的特征关系，从而丰富了模式识别期间终端节点的区分因素。此外，我们提出了一种技术，用于适应长时间指纹识别中数据模式的时间变化的分类器。我们的方法不断监测训练数据中分类器的性能。当准确度低于预定阈值时，我们将分类器替换为在最新数据上训练的另一个分类器。我们称之为ADABIND（带双向依赖的自适应指纹识别）。我们的贡献总结如下。

• 我们提出了一种新的特征提取方法BIND，用于指纹识别加密流量以识别终端节点。我们特别考虑在相反方向的数据包序列之间的关系。

• 我们提出了一种名为ADABIND的方法，其中机器学习分类器适应长时间指纹识别时发生的行为模式变化。我们不断监测分类器的性能，并以在线方式重新训练它。

在本节中，我们介绍了有关交通分析的相关现有研究，特别是在WFIN和AFIN中。

# 2.1 网站指纹识别

用户访问网站的在线活动可以使用匿名网络（如Tor）进行隐藏[14]。Tor提供低延迟加密连接到互联网，同时通过流水线随机化的过程对连接进行匿名化。在Tor网络中形成了三个中继节点的电路，由入口节点、出口节点和随机选择的中继节点组成。大约每使用10分钟重新建立电路连接[2]。在这种情况下进行指纹识别很困难，因为即使同一网站的不同访问也可能由于使用了不同的Tor电路而呈现完全不同的流量模式。尽管如此，WFIN这个具有挑战性的问题在研究界中广受欢迎，有许多研究[6,7,21,25,27,36]提出了执行指纹识别和防御它的技术。归纳假设是每个网站在从其服务器到用户浏览器中传送数据的模式方面是独特的。此外，每个网站的内容也是独特的。利用这个假设，网站指纹识别场景以一种通常被认为是针对用户隐私的攻击的统计模型来预测与给定跟踪相关联的网站名称。而防御机制则探索方法来减少这样的攻击模型的有效性。

# 2.1.1 攻击

主要的攻击形式是使用从不同网站收集的跟踪训练分类器，其中每个跟踪表示为一组独立特征。与每个跟踪相关联的网络数据包中的信息被总结成直方图特征向量，其中特征包括数据包长度（大小）和方向（与[25]中使用的一样）。此外，Panchenko等人[28]介绍了从一组数据包中提取的特征的组合，称为Size Markers或暴发。暴发是沿同一方向（上传或下载）传输的连续数据包序列。诸如暴发大小之类的特征是通过将暴发内每个数据包的长度相加来计算的。这些特征以及其他特征，如唯一数据包大小、HTML标记和传入和传出数据包的百分比，组成了跟踪的特征向量。Dyer等人[17]也使用带宽和网站上传时间作为特征。

## 

---

 ## 原文[2/13]： 

 
A recent work by Panchenko et al. [27] proposes a sampling process on aggregated features of packets to generate overall trace features. Importantly, Cai et al. [7] obtained high classiﬁcation accuracy by 

selecting features that involve packet ordering, where the cumulative sum of packet sizes at a given time in each direction is considered. 

This feature set was also conﬁrmed to provide improved classiﬁcation accuracy in [36]. It indicates that features capturing relationships among packets in a trace are effective in distinguishing different websites (or end-nodes). In our paper, we focus on extracting such capability from traces in a novel fashion by capturing relationships between consecutive bursts in opposite directions.

 178 

While these features are used to train a classiﬁer, e.g. Naïve Bayes [17] and Support Vector Machine (SVM) [28], studies have 

identiﬁed two major settings under which website ﬁngerprinting can be performed. First, the user is assumed to access only a small set of 

known websites. This restriction simpliﬁes the training process since the attacker can train a model in a supervised manner by considering 

traces only from those websites. This form of classiﬁcation is known as closed-world. However, such a constraint is not valid in general as a 

user can have unrestricted access to a large number of websites. In this case, training a classiﬁer by collecting trace samples from all websites to perform multi-class classiﬁcation is unrealistic. Therefore, an 

adversary is assumed to monitor access to a small set of websites called the monitored set. The objective is to predict whether a user accesses one of these monitored websites or not. This binary classiﬁcation setting is called open-world. Wang et al. [36] propose a feature 

weighting algorithm to train a k-Nearest Neighbor (k-NN) classiﬁer in the open-world setting. They utilize a subset of traces from the 

monitored websites to learn feature weights which are used to improve classiﬁcation. In this paper, we evaluate our proposed feature extraction approach on both these settings. Particularly for the open-world case, we utilize the feature weighting method proposed in [36] to perform a comparative study of feature extraction techniques. A study by Juarez et at. [23] observes and evaluates various 

assumptions made in previous studies regarding WFIN. These include page load parsing by an adversary, background noise, sequential 

browsing behavior of a user, replicability, and staleness in training data with time, among others. While recent studies [18,38] have addressed each of these issues by relaxing appropriate assumptions, the issue of address the issue of staleness in training data over time within their k-NN model [36] speciﬁc to open-world. They score the training data consisting of traces based on model performance of 20 nearest 

neighbors. However, this methodology cannot be generalized, i.e., it is not applicable if one uses a classiﬁer other than k-NN. Moreover, it is also not applicable to the closed-world setting. In this paper, we 

introduce a generic method to update the classiﬁer model in WFIN and AFIN over long periods of time.

 2.1.2 Defense 

Since a successful attack depends on the characteristic network 

packet features used to train a model, defenses against WFIN involve disguising these features to reduce distinguishing patterns in network traces. Such defense mechanisms vary from padding packets with extra bytes, to morphing the website packet length distribution such that it appears to come from another target distribution (i.e., a different website) [17]. In packet padding, each packet size in the trace is increased to a certain value depending on the padding method used. These methods include Pad-to-MTU [17], Direct Target Sampling(DTS), and Trafﬁc Morphing (TM) [40].

 Pad-to-MTU pads each packet to the maximum size limit in TCP 

protocol (Maximum Transmission Unit or MTU). With all packet sizes equal, the use of the packet length feature for obtaining deterministic patterns might be less effective. However, this method is not widely when most of the packets in a trace are of length less than MTU. 

Nevertheless, early studies [25] showed that attacks with a considerable success are possible even when defenses like packet padding are used. This led to a study in [40] that introduced more sophisticated distribution-based padding methods such as DTS and TM. In DTS, using random sampling, the distribution of the packet length in a trace belonging to a website is made to appear similar to the packet   

---

 ## 翻译[2/13]：
 

最近，Panchenko等人提出了一种对数据包聚合特征进行采样的过程，以生成整个跟踪特征。重要的是，Cai等人通过选择涉及数据包排序的特征并考虑每个方向上给定时间的数据包大小的累积和，获得了高分类精度。这个特征集在[36]中也被证明可以提供改进的分类精度。这表明，捕捉跟踪中数据包之间的关系的特征可以有效地区分不同的网站（或终端节点）。在本文中，我们专注于以新颖的方式从跟踪中提取这种能力，即捕获相反方向连续突发之间的关系。

虽然这些特征被用于训练分类器，例如Naïve Bayes [17]和支持向量机（SVM）[28]，但研究已经确定了进行网站指纹识别的两种主要设置。首先，假设用户只访问少量已知网站。这种限制简化了训练过程，因为攻击者可以通过只考虑来自那些网站的跟踪来监督式地训练模型。这种分类被称为封闭式。然而，一般情况下，这种限制并不成立，因为用户可以不受限制地访问大量网站。在这种情况下，通过收集来自所有网站的跟踪样本来训练分类器以进行多类别分类是不现实的。因此，假设敌方只监视访问少量网站的用户所访问的情况。目标是预测用户是否访问这些受监视的网站。这种二元分类设置被称为开放式。Wang等人[36]提出了一种特征加权算法，用于在开放世界设置中训练k-Nearest Neighbor（k-NN）分类器。他们利用一部分来自受监视网站的跟踪来学习特征权重，这些权重用于提高分类精度。在本文中，我们评估了我们提出的特征提取方法在这两种情况下的应用。特别是对于开放式情况，我们利用[36]中提出的特征加权方法来进行特征提取技术的比较研究。Juarez等人的一项研究[23]观察并评估了之前在WFIN的研究中所做的各种假设。这些包括由敌方进行的页面加载解析、背景噪声、用户的顺序浏览行为、可复制性以及随时间变化的训练数据的陈旧程度等。尽管最近的研究[18,38]通过放宽相应的假设解决了这些问题之一，但是解决随时间流逝在他们专门针对开放式k-NN模型[36]中的训练数据的问题仍然是一个挑战。他们根据20个最近邻模型的性能对包含跟踪的训练数据进行评分。然而，这种方法不能推广，即如果使用的是除k-NN之外的分类器，则不适用。此外，它也不适用于封闭式设置。在本文中，我们引入了一种通用方法，用于长时间内更新WFIN和AFIN中的分类器模型。

由于成功的攻击取决于用于训练模型的特征网络数据包的特征，因此WFIN的防御涉及掩盖这些特征以减少网络跟踪中的可区分模式。这种防御机制因填充数据包而变得多样化，包括向数据包填充额外的字节，或者使网站数据包长度分布变形，使其看起来来自于另一个目标分布（即不同的网站）[17]。在数据包填充中，跟踪中的每个数据包大小都增加到特定的值，具体取决于使用的填充方法。这些方法包括Pad-to-MTU [17]、Direct Target Sampling（DTS）和Traffic Morphing（TM）[40]。

Pad-to-MTU将每个数据包填充到TCP协议的最大大小限制（最大传输单元或MTU）中。由于所有数据包大小相等，使用数据包长度特征来获得确定性模式的效果可能会降低。然而，当跟踪中大部分数据包的长度都小于MTU时，这种方法并不常用。尽管如此，早期的研究[25]表明，即使使用数据包填充等防御措施，攻击仍然具有相当的成功率。这导致[40]的一项研究引入了更复杂的基于分布的填充方法，例如DTS和TM。在DTS中，使用随机采样，使属于网站的跟踪的数据包长度分布看起来类似于分布在另一个目标分布（即不同的网站上）中的数据包长度分布。

## 

---

 ## 原文[3/13]： 

 
length distribution of another website. This requires less overhead than Pad-to-MTU. TM further improves DTS by using a cost minimization function between two websites to minimize packet padding, while 

maximizing similarity between them. In our study, we evaluate BIND by applying these padding techniques to packets while performing the closed-world settings in website ﬁngerprinting. In the case of open-world setting, Dyer et al. [17] introduced a defense mechanism, called Buffered Fixed Length Obfuscator (or 

BuFLO), that not only uses packet padding, but also modiﬁes packet timing information by sending packets in ﬁxed intervals. Cai et 

al. [6] improved BuFLO and introduced a lighter defense mechanism, called Tamaraw, which considers different time intervals for uplink and downlink packets in the open-world setting. We utilize these mechanisms in the open-world setting to evaluate BIND.

 2.2 App Fingerprinting 

An increase in popularity of smartphone applications has attracted researchers to study the issues of user privacy and data security in apps developed by third-party developers [35]. In particular, many studies have proposed methods to perform trafﬁc analysis while a user uses an app. Dai et al. [12] ﬁrst proposed a method to identify an app by using the request-response mechanisms of API calls found in HTTP packets. They perform UI fuzzing on apps whose network packets are captured using an emulator. Similarly, [26] proposes a method to ﬁngerprint 

apps using comprehensive trafﬁc observations. These studies perform app identiﬁcation (or ﬁngerprinting) using only HTTP trafﬁc. Such 

methods cannot be applied on HTTPS trafﬁc since the packet content is encrypted and not readily available. explore varied applications including smartphone ﬁngerprinting [33], user action identiﬁcation [9,10], user location tracking [3], and app identiﬁcation [26]. They use packet features such as packet 

length, timing information, and other statistics to build classiﬁers for identiﬁcation (or prediction). Note that this is similar to the WFIN both HTTP and HTTPS data. They use features such as burst statistics the same TCP session. They train a random forest classiﬁer (ensemble of weak learners) and a support vector machine (SVM) using features extracted from network trafﬁc of about 110 apps from the Google play store. Evaluation of their method is similar to the closed-world setting of WFIN, where network trafﬁc from apps considered for training and testing the model belong to a closed set, i.e., the user has access to only a ﬁnite known set of apps. The method resulted in an overall accuracy of 86.9% using random forest, and 42.4% using SVM. These results are based on a small dataset of apps which may have both HTTP and HTTPS trafﬁc. Furthermore, they only show a closed-world setting. However, with a large number of apps present on various app stores, these results may not reﬂect a realistic scenario of the open-worldsetting in AFIN.

 Similar to that of WFIN, the open-world setting in AFIN assumes that the man-in-the-middle monitors the use of a small set of apps called the monitored set. The goal is to determine whether a user is running an app that belongs to this set. In our evaluation, we use our proposed technique for trafﬁc analysis on a larger dataset of apps that only use HTTPS for connecting to remote services. Contrary to 

WFIN where the network is anonymized, apps do not use an anonymity network. However, the effect of anonymization is similar to that of WFIN. In WFIN, anonymization results in removal of destination 

website identiﬁers (i.e., IP address). In AFIN, apps connect to multiple remote hosts deriving remote services from them. However, multiple 

apps may connect to the same host. A mere list of hosts or IP addresses is not sufﬁcient to deterministically identify an app. This property effectively anonymizes such apps with respect to the network. We therefore rely on trafﬁc analysis to perform AFIN. In this paper, we

 179 Table 1: Features from Packets, Uni-Bursts, and Bi-Bursts. show the applicability of both closed-world and open-world settings while utilizing the BIND feature extraction method.

 3. PROPOSED APPROACH 

In this section, we present the methodology to extract the BINDfeatures, and detail the ADABIND approach.

 3.1 Features 

With encrypted payload of each packet in a trace, we extract features from packet headers only. The main idea is to extract features from 

consecutive bursts to capture any dependencies that may exist between them. As illustrated in Figure 2, we call the burst directed from a 

user/client (or app) to server (e.g., burst a), an uplink uni-burst (or Up uni-burst), and the burst directed from server to the user, a downlink 

uni-burst (or Dn uni-burst) (e.g., burst b). Similar to packets, a burst or uni-burst has features such as size (or length), time, and direction. Uni-burst size is the summation of lengths of all its packets. Packet   

---

 ## 翻译[3/13]：
 

分布的另一个网站的长度。这比Pad-to-MTU需要更少的开销。TM通过在两个网站之间使用成本最小化函数来使用填充数据包来进一步改进DTS，从而最小化数据包的填充，同时最大化它们之间的相似性。在我们的研究中，我们通过应用这些填充技术对数据包进行BIND来评估它们在网站指纹中的闭合环境中的应用。在开放世界环境中，Dyer等人[17]引入了一种防御机制，称为缓冲固定长度混淆器（或BuFLO），它不仅使用数据包填充，而且还通过在固定时间间隔内发送数据包来修改数据包时序信息。 Cai等人[6]改善了BuFLO并引入了一种较轻的防御机制Tamaraw，在开放世界环境中考虑了上行和下行数据包的不同时间间隔。我们在开放世界环境中利用这些机制来评估BIND。

#2.2 应用指纹识别
智能手机应用程序的普及引起了研究人员对第三方开发者开发的应用程序中的用户隐私和数据安全问题的关注[35]。特别是，许多研究提出了方法用于在用户使用应用程序时执行流量分析。Dai等人[12]首先提出了一种通过使用在HTTP数据包中找到的API调用的请求-响应机制来识别应用程序的方法。他们对使用仿真器捕获的应用程序的网络数据包进行UI模糊测试。同样，[26]提出了一种使用全面的流量观察来指纹识别应用程序的方法。这些研究仅使用HTTP流量执行应用程序识别（或指纹识别）。这样的方法不能应用于HTTPS流量，因为数据包内容是加密的且不易获得。探索不同的应用程序，包括智能手机指纹识别[33]，用户操作识别[9,10]，用户位置跟踪[3]和应用程序识别[26]。他们使用数据包特征，如数据包长度，时间信息和其他统计数据来构建用于识别（或预测）的分类器。请注意，这类似于WFIN对HTTP和HTTPS数据的处理。他们使用爆发统计信息等特征数据，这些数据来自相同的TCP会话。他们还使用了一些从谷歌Play商店的近110个应用的网络流量中提取的特征训练随机森林分类器（弱学习算法的集合）和支持向量机（SVM）。他们的方法的评估类似于WFIN的闭合环境设置，其中用于训练和测试模型的应用程序的网络流量属于一个封闭集，即用户只能访问有限的已知应用程序集。使用随机森林获得了86.9％的总体准确度，使用SVM获得了42.4％的准确度。这些结果是基于可能具有HTTP和HTTPS流量的一小组应用程序的数据集。此外，他们仅显示了一个闭合环境设置。然而，随着各种应用商店中存在大量应用程序，这些结果可能不能反映AFIN的开放世界环境的现实情况。

与WFIN类似，AFIN中的开放世界假设是中间人监视称为监视集的一小组应用程序的使用。目标是确定用户是否运行属于该集合的应用程序。在我们的评估中，我们使用我们提议的流量分析技术对仅使用HTTPS连接到远程服务的更大的应用程序数据集进行评估。与WFIN不同，网络没有匿名处理，应用程序不使用匿名网络。然而，匿名化的效果与WFIN相似。在WFIN中，匿名化导致删除目标网站标识符（即IP地址）。在AFIN中，应用程序连接到多个远程主机并从中获取远程服务。但是，多个应用程序可能连接到同一主机。仅列出主机或IP地址列表不足以确定性地识别应用程序。此属性有效地将此类应用程序匿名化相对于网络。因此，我们依赖于流量分析来执行AFIN。在本文中，我们展示了使用BIND特征提取方法评估闭式和开式世界设置的适用性。

# 3. 提议的方法
在本节中，我们提出从包头中提取BIND特征的方法，并详细介绍ADABIND方法。

# 3.1 特征
对于跟踪中每个数据包的加密有效载荷，我们仅从包头中提取特征。我们的主要思想是从连续的爆发中提取特征，以捕获它们之间可能存在的任何依赖关系。如图2所示，我们将从用户/客户端（或应用程序）到服务器的爆发（例如爆发a）称为上行单向爆发（或Up uni-burst），将从服务器到用户的爆发称为下行单向爆发（或Dn uni-burst）（例如爆发b）。类似于数据包，爆发或单向爆发具有大小（或长度）、时间和方向等特征。单向爆发大小是其所有数据包的长度总和。

## 

---

 ## 原文[4/13]： 

 
time is the departure/arrival timestamp in the uplink/downlink direction, measured near the user-end of the network by a man-in-the-middle. Uni-burst time is the difference between the last packet’s timestamp and the ﬁrst packet’s timestamp within a burst, i.e., the time taken to transmit all packets of a burst in a speciﬁc direction. Here, the term burst and uni-burst are equivalent. The name uni-burst emphasizes on the fact that features are extracted from a single burst, as opposed to Bi-Burst which is a tuple formed by a sequence of two adjacent uni-bursts in opposite direction (e.g., burst b and c in Figure 2). Bi-Burst features. Features extracted from Bi-Bursts are as follows. 1. Dn-Up-Burst size: Dn-Up-Burst is a set of tuples formed by downlink (Dn)  uplink (Up) consecutive bursts. Here, unique tuples are formed according to the corresponding uni-burst lengths where each tuple forms a new feature. 2. Dn-Up-Burst time: This set of features considers unique 

consecutive uni-burst time tuples between adjacent Dn uni-burst and Up uni-burst sequences. 

3. Up-Dn-Burst size: Similar to Dn-Up-Burst size features, these Dn uni-burst sequences. 

4. Up-Dn-Burst time: Similar to Dn-Up-Burst time features, this set of features considers burst time tuples formed by adjacent Up uni-burst and Dn uni-burst sequences. In each trace, we count such unique tuples to generate a set of 

features. To overcome dimensionality issues associated with burst sizes, quantization [15] is applied to group bursts into correlation sets (e.g.,based on frequency of occurrence).

 we also use burst size and burst time features. Previous studies [17] only consider total trace time as a feature, contrary to the burst time 

feature we use in this paper. Furthermore, we also consider the count of packets within a burst as a feature. In order to capture variations of the Figure 2: An example illustrating BIND Features. 

packet features, we use an array of unique packet lengths as well. The are concatenated to form a large array of features (histograms) to be extracted from each trace. A set of multiple traces represented in thismanner forms the training and testing set.

 Example. Figure 2 depicts a simple trace where packet sequences 

between uplink and downlink are shown. Each packet in the ﬁgure has size s in bytes and time t in milliseconds. We set time for the ﬁrst 

packet in the trace to zero, as a reference. An example of a uni-burst is shown as burst a, whose size is 500, computed by adding packet sizes s = 200 and s = 300 that form the burst. Its time is computed as 10, which is the absolute time difference between the last packet (t = 10) and the ﬁrst packet (t = 0) in the burst. Similarly, a Bi-Burst example is shown as well, formed with a combination of bursts b and c. This is denoted as Dn-Up-Burst. In this case, the Bi-Burst tuple using the burst size (i.e., Dn-Up-Burst size) is represented as {DnUp_2300_400}, where 2300 is the burst size of b, and 400 is the burst size of c. We count the number of such unique tuples in the trace. In this case, thecount for {DnUp_2300_400} is 1.

 3.2 Learning 

In the closed-world setting, we use the BIND features to train a 

support vector machine (SVM) [11] classiﬁer. SVM applies convex op linearly separated feature space. Whereas in the open-world setting, using the BIND features, we apply the weighted k-Nearest Neighbor (k-NN) approach proposed in [36]. Feature weights are computed using traces from the monitored set. During testing of traces with

 180 Figure 3: Illustration of ADABIND. 

unknown class labels, these feature weights are applied. Majority class voting among k-Nearest Neighbors is performed to predict class label of a test trace. Additionally, we also use a Random Forest classiﬁer in the open-world setting. Instead of performing feature weighing, which is computationally expensive, we use a set of weak learners to form an ensemble of decision trees (random forest).

 3.2.1 Static Learning 

Typically, previous studies (mentioned in §2.1) have focused on 

performing ﬁngerprinting by collecting traces for a short period of time. Classiﬁers are trained on traces collected within this time period, and used to predict class labels thereafter. We refer to this type of classiﬁer training as static. On the contrary, WFIN and AFIN can be viewed as a continuous process involving trace collection over a long period of time. Moreover, data collection is time consuming. Changes in data content transmitted between end-nodes affect patterns captured in the model. drastically affects classiﬁcation performance.

 3.2.2 Adaptive Learning 

We now present the details of ADABIND. In this section, we show how we model encrypted data ﬁngerprinting in an adaptive manner. As discussed in §3.2.1, over time, the data patterns of the current traces may be different from the patterns in previously seen training traces. This is known as concept drift [19,20]. To address this challenge, the model has to be updated (re-trained) regularly. We study the effect ofre-training as follows.

 Fixed update. One simple approach is to apply ﬁxed updates to   

---

 ## 翻译[4/13]：
 

时间是上下行方向上离用户端近的一个中间人测量的出发/到达时间戳。Uni-Burst时间是在一个突发中最后一个数据包时间戳和第一个数据包时间戳之间的差值，即在特定方向上传输一个突发所需的时间。在这里，术语“突发”和“Uni-Burst”是等价的。Uni-Burst名称强调了从单个突发中提取特征的事实，而不是由两个相邻的相反方向的单个突发（例如图2中的突发b和c）形成的双向突发。双向突发特征。从双向突发中提取的特征如下。1.下传-上传突发大小：Dn-Up-Burst是由下传(Dn)上传(Up)连续突发形成的元组集。在这里，根据相应的Uni-Burst长度形成唯一的元组，每个元组形成一个新特征。2.下传-上传突发时间：该特征集考虑相邻的Dn Uni-Burst和Up Uni-Burst序列之间的唯一连续Uni-Burst时间元组。3.上传-下传突发大小：类似于Dn-Up-Burst大小特征，这些是由不同的上行Uni-Burst序列组成。4.上传-下传突发时间：类似于Dn-Up-Burst时间特征，这个特征集考虑由相邻的Up Uni-Burst和Dn Uni-Burst序列形成的突发时间元组。在每个跟踪中，我们计算这样的唯一元组以生成一组特征。为了克服与突发大小相关的维数问题，应用量化[15]将突发分组成相关集合（例如基于出现频率）。

我们还使用突发大小和突发时间特征。以前的研究[17]只考虑总跟踪时间作为一个特征，与我们在本文中使用的突发时间特征相反。此外，我们还考虑了突发中数据包的计数作为特征。为了捕捉数据包特征的变化，我们使用一组唯一数据包长度的数组。它们被链接成一组大的特征数组（直方图），从每个跟踪中提取。用此方法表示的多个跟踪集合形成训练和测试集。

例如。图2显示了一个简单跟踪，显示上行和下行之间的数据包序列。图中的每个数据包大小为s(bytes)，时间为t(ms)。我们将跟踪中的第一个数据包的时间设置为参考值0。突发a是示例，其大小为500，通过将形成突发的数据包大小s=200和s=300相加来计算。它的时间被计算为10，这是突发中最后一个数据包（t=10）和第一个数据包（t=0）之间的绝对时间差。类似地，还展示了一个双向突发示例，由b和c突发的组合形成。这被表示为Dn-Up-Burst。在这种情况下，使用突发大小（即Dn-Up-Burst大小）表示的双向突发元组表示为{DnUp_2300_400}，其中2300是b的突发大小，400是c的突发大小。我们计算跟踪中这样的唯一元组数量。在这种情况下，{DnUp_2300_400}的计数为1。

# 3.2学习

在封闭的世界环境中，我们使用BIND特征训练支持向量机（SVM）[11]分类器。SVM在线性可分特征空间中应用凸面。而在开放的世界环境中，使用BIND特征，我们采用[36]中提出的加权k-Nearest Neighbor（k-NN）方法。使用来自监测集的跟踪计算特征权重。在具有未知类标签的跟踪测试期间，应用这些特征权重。在k个最近的邻居中进行多数类投票，以预测测试跟踪的类标签。此外，我们还在开放世界环境中使用随机森林分类器。我们使用一组弱学习器形成决策树的集合（随机森林），而不是执行特征加权，这种方法计算成本较高。

#3.2.1静态学习

通常，以前的研究（在第2.1节中提到）侧重于收集短时间内的跟踪来进行指纹识别。这段时间内收集的跟踪用于训练分类器，之后用于预测类标签。我们将此类分类器训练称为静态分类器。相反，WFIN和AFIN可以视为涉及长时间跟踪收集的连续过程。此外，数据收集是耗时的。终端节点之间传输的数据内容的变化会影响模型中捕获的模式，从而显著影响分类性能。

# 3.2.2自适应学习 

我们现在介绍ADABIND的详细信息。在本节中，我们展示了如何以自适应方式建立加密数据指纹。如第3.2.1节所述，随着时间的推移，当前跟踪的数据模式可能与以前看到的训练跟踪中的模式不同。这被称为概念漂移[19,20]。为了应对这个挑战，模型必须定期更新（重新训练）。我们按照以下方式研究重新训练的效果：

固定更新。一种简单的方法是对模型应用固定更新。

## 

---

 ## 原文[5/13]： 

 
re-train the model periodically. We refer to this approach as BINDFUP (BIND Fixed UPdate). BINDFUP updates the model periodically, regardless of any concept drift that may happen. The model will be re-trained regularly (e.g., at the end of every week) with freshly 

obtained training data. There are two possible scenarios, early update and late update. In early update, BINDFUP updates the model in a way that ensures no concept drift in data. Although this update is more 

accurate and stable, it may suffer from unnecessary re-training which will add signiﬁcant overhead to the classiﬁcation process. On the other hand, late update may miss possible concept drift in data over time which affects the overall performance of the model. the model whenever there is a drift between the current data and previously seen training data. R is a training window that builds the model, while S is a sliding window that probes this model for any possible concept drift (i.e., model needs update). Algorithm 1 portion of data as a training window to initialize the ADABIND model Algorithm 1: BINDDUP Table 2: Statistics for Website Fingerprinting datasets in theopen-world setting.

 

(lines 2 and 3). Then, the subsequent instances are considered within a sliding window to validate the performance of this model over time 

(lines 5 and 6). If the accuracy drops below a predeﬁned threshold (line 7), the initial ADABIND model becomes obsolete (i.e., concept drift) and the training window moves (line 8) to get new instances to re-train updated model to test incoming new data in a continuous fashion.

 4. EVALUATION 

In this section, we present the empirical results of using BIND for WFIN and AFIN, comparing it with other existing methods.

 4.1 Datasets 

We use two existing datasets for evaluating WFIN, one using HTTPS and the other using the Tor anonymity network, referred to as HTTPS research on trafﬁc ﬁngerprinting. For AFIN, we collect our own dataset from apps that use the HTTPS protocol. Website Datasets. The ﬁrst dataset presented in [25], which we denote as HTTPS, was collected while browsing websites using the HTTPS protocol along with a proxy server to imitate an anonymity 

network. The authors followed a ranking procedure to select the most accessed websites in their school department. The second dataset is described in [36]. This dataset is collected by capturing packets 

generated from a browser connected to the Tor anonymity network. We denote this dataset as TOR. HTTPS consists of 1000 websites with 200 traces each. For WFIN, we evaluate the closed-world setting by randomly picking a subset of 

these 1000 websites. For the open-world setting, we randomly select 30 websites as the monitored set, and the rest as the non-monitored one. The other dataset (TOR) consists of two sets of traces. The ﬁrst is a set of 100 websites that have 90 traces each. These websites were selected from a list of blocked websites by some countries. We use this for the closed-world experiments. The second set consists of 

5000 websites that have one trace each. These websites were selected

 181 Table 3: Dataset statistics for App Fingerprinting in the open-world setting.

 Figure 4: Illustration of the app trace data collection process from Alexa’s top websites [1]. In the open-world setting, we use the set of 100 websites as monitored, and the set of 5000 websites as in Table 2. These two datasets enable us to perform an unbiased comparison of BIND with other competing methods. App Dataset. For AFIN, we evaluate BIND using a dataset that we collected by executing multiple Android apps on a Samsung Galaxy S device, running Android version 4.3.1. We randomly select about 

30,000 apps from three different categories in Google Play Store. The categories include Finance, Communication, and Social. We refer to them as APP-FIN, APP-COMM, and APP-SOCIAL respectively. We then install and launch these apps on the phone which is connected to the Internet via a wireless router. Each trace per app is collected over a 30-sec period passively using a mirroring switch at the wireless router. Figure 4 illustrates this data collection setup. We ﬁltered the captured trafﬁc to contain packets from ports 80, 8080, and 443. We then identify apps that use only HTTPS data from the captured traces. These traces from such apps are then used to perform the closed-world and open-world AFIN. It is important to note that we uninstall each app during further trace generation. Similar to WFIN, multiple traces of apps are required to train a classiﬁer in the closed-world and open-world settings. We use the 

APP-FIN dataset for performing the closed-world experiments as we 

capture multiple traces for each app. We only capture a single trace per app for APP-COMM and APP-SOCIAL to be used for the open-world experiments as the non-monitored set. The dataset statistics for the 

open-world setting are shown in Table 3. Note that in the closed-world setting, we only evaluate using apps from APP-FIN. In the case of 

open-world, the monitored apps are considered only from APP-FIN and the non-monitored apps are considered from all categories shown inTable 3.

 a few interesting statistics that would further motivate the problem of AFIN. Figure 5 shows the percentage of apps that use HTTP and HTTPS data at launch in our initial set of 30, 000 apps. Observe that Figure 5: Empirical Statistics of Android Apps Table 4: Trafﬁc Analysis Techniques used for the evaluation   

---

 ## 翻译[5/13]：
 

定期重新训练模型。我们称之为BINDFUP（BIND Fixed Update）方法。BINDFUP无论发生任何概念漂移，都会定期更新模型。该模型将定期重新训练（例如，在每个星期末）使用新的训练数据。有两种可能的情况，即早期更新和晚期更新。在早期更新中，BINDFUP以确保数据中没有概念漂移的方式更新模型。虽然此更新更准确和稳定，但可能会遭受无谓的重新培训，这会给分类过程增加显着的开销。另一方面，晚期更新可能会错过随着时间流逝可能出现的数据概念漂移，影响模型的整体表现。只要出现当前数据与先前观察到的训练数据之间存在漂移，就可以使用S作为滑动窗口，不断探测模型中的所有可能的概念漂移（即模型需要更新）。

#4.评估

在本节中，我们介绍了使用BIND进行WFIN和AFIN的实证结果，并与其他现有方法进行了比较。

#4.1 数据集

我们使用两个现有的数据集用于评估WFIN，一个使用HTTPS，另一个使用Tor匿名网络，称为HTTPS研究网络流量指纹。对于AFIN，我们从使用HTTPS协议的应用程序中收集我们自己的数据集。网站数据集。第一个数据集[25]中提供了描述，我们将其表示为HTTPS，是使用HTTPS协议浏览网站并使用代理服务器来模拟匿名网络时收集的。作者遵循排名程序选择了其学校部门中访问量最大的网站。第二个数据集在[36]中描述。该数据集通过捕获连接到Tor匿名网络的浏览器生成的数据包收集而来。我们将其称为TOR。HTTPS包含1000个网站，每个网站包含200个示踪数据。对于WFIN，我们通过随机选择这1000个网站的子集来评估闭环设置。对于开放性设置，我们随机选择30个网站作为监测集，其余网站作为非监测集。第二个数据集（TOR）包含两组示踪数据。第一组是有90个示踪数据的100个被某些国家列为封锁网站的网站。我们将其用于闭环实验。第二组包含5000个每个网站均有一个示踪数据的网站。这些网站是经过很好选择的[6, 17]。这两个数据集使我们能够与其他竞争方法进行公正的比较。应用数据集。对于AFIN，我们使用我们在三星Galaxy S设备上执行多个Android应用程序收集的数据集进行评估，运行Android 4.3.1版本。我们从Google Play Store中随机选择大约30,000个应用程序，分别来自财务、通信和社交三个不同的类别。我们将其称为APP-FIN、APP-COMM和APP-SOCIAL。然后，我们在连接到无线路由器的手机上安装并启动这些应用。每个应用的示踪是在30秒的时间段内被动收集，使用无线路由器上的镜像交换机。图4说明了这个数据收集设置。我们过滤掉从80、8080和443端口发送的数据包。我们然后识别仅使用HTTPS数据的应用程序。这些应用程序的示踪数据用于执行闭环和开放性AFIN。同WFIN类似，需要多个应用程序示踪数据以在闭环和开放性设置中训练分类器。我们在APP-FIN数据集中使用多个应用示踪数据进行闭环实验。我们仅为APP-COMM和APP-SOCIAL捕获单个应用程序示踪数据，用于用于开放性实验，作为非监测集。开放性设置的数据统计信息如表3所示。请注意，在闭环设置中，我们仅使用来自APP-FIN的应用进行评估。在开放世界的情况下，受监控的应用仅来自APP-FIN，而非监测应用来自表3中显示的所有类别。

一些有趣的统计数据进一步激发了AFIN问题。图5显示了在我们最初设置的30,000个应用中，在启动时使用HTTP和HTTPS数据的应用程序的百分比。注意到图5：Android应用的实证统计数据
表4：用于评估的流量分析技术

## 

---

 ## 原文[6/13]： 

 
most apps use HTTP along with HTTPS while a sizable portion of apps obtained a list of IP addresses from HTTPS apps in each category We found a total of 1115 unique IP addresses for APP-FIN, 820 for APP-COMM, and 900 for APP-SOCIAL. Additionally, each app 

connects to 3 different IP addresses on average over the whole dataset. This clearly indicates that the IP addresses found on HTTPS trafﬁc overlap across apps, and do not provide sufﬁcient information toidentify the app generating a trace by itself.

 4.2 Experimental Settings 

Using these datasets, we perform our analysis on both closed world and open-world settings. For a comparative evaluation, we 

consider existing trafﬁc analysis techniques developed for WFIN. These techniques are listed in Table 4. The table details the features and 

classiﬁers used for our evaluation in both Closed-world (Closed) and Open-world (Open) settings. For brevity of representation, we term 

websites (in the case of WFIN) or apps (in the case of AFIN) as entities. classiﬁer (SVM) in the closed-world setting. We refer to this approach as BINDSVM as shown in Table 4. In our experiments, we use a publicly available library called LibSVM [8] with a Radial Basis 

Function (RBF) kernel having the parameters Cost = 1.3 × 105 and γ = 1.9 × 10−6 (following recommendations in [28]). We consider varied subsets of entities to evaluate the feature set. Particularly, we use 16 randomly selected traces per entity (class) for training a

 182 experiment, we chose the number of selected (monitored) entities in{20, 40, 60, 80, 100}.

 Open-world. For the open-world scenario, as discussed in §3.2, we use two classiﬁcation methods with the BIND features. First, we use the weighted k-NN mechanism proposed in [36]. Speciﬁcally, we use k = 1 since it is shown to produce the best results on the TOR dataset in [36]. We denote this method as BINDWKNN as shown in Table 4. Furthermore, we also use the Random Forest classiﬁer 

with BIND features, denoted as BINDRF in Table 4. We use a set of 100 weak learners to form an ensemble of decision trees. We use the monitored and non-monitored traces mentioned in Tables 2 and 3 areconsidered for evaluation.

 Evaluation Measure. The results of the closed-world evaluation are measured by computing the average accuracy of classifying the correct class for all test traces. We randomly select traces from the corresponding dataset and repeat each experiment 10 times with different entities and traces. Average accuracy is computed across these experiments. In the open-world evaluation, we measure the true positive rate (TPR) and false positve rate (FPR) of the binary classiﬁcation. These are deﬁned as follows: TPR = FPR = F P +T N . Here, TP (True Positive) is the number of traces which are monitored, and predicted as monitored by the classiﬁer. FP (False Positive) is the number of traces which are non-monitored, but predicted as monitored. TN (True Negative) is the number of traces which are non-monitored and predicted as non-monitored. FN (False Negative) is the number of traces which are monitored, but predicted as non-monitored. We perform a 10-fold cross validation on each dataset, which gives randomized instance ordering. In order to evaluate the performance of BIND against defenses discussed in §2.1, we consider one of the most sophisticated and 

complex defenses, Trafﬁc Morphing (TM). Furthermore, to evaluate BIND against existing approaches, for the open-world setting on the TOR dataset, we apply the Tamaraw defense mechanism, designed speciﬁcally for Tor, as evaluations in [6,36] show that this defenseperforms exceptionally well against TOR.

 4.3 Experimental Results 

We use the notations given in Table 2 and Table 3 to denote theWFIN and AFIN datasets respectively.

 4.3.1 Trafﬁc Analysis 

We ﬁrst perform WFIN and AFIN experiments in the closed-world setting. Here, a set of randomly chosen entities are classiﬁed using presented in Table 5 using the HTTPS and TOR datasets for WFIN, and the APP-FIN dataset for AFIN. In some cases, we can see BINDSVM performs comparatively closer to or lower than the other competing methods, while outperforming them in other cases. For example, with 80 websites considered, the average accuracy of BINDSVM (BIND 

using SVM) on the HTTPS dataset is 88.4%. This is marginally greater than 88.3% obtained from the P method. Similarly in AFIN, BIND resulted in an average accuracy of 87.8%, compared to a marginally 

better accuracy of 88% resulting from the P method. Moreover for the TOR dataset, it is not surprising that the OSAD method performs the best in all experimental settings since it uses a distance measure that is speciﬁcally applicable to Tor data. In the closed-world setting, most methods listed in Table 4 use features that overlap or hold   

---

 ## 翻译[6/13]：
 

大多数应用程序使用HTTP与HTTPS，而相当一部分应用程序从每个类别的HTTPS应用程序中获取了IP地址列表。我们为 APP-FIN 找到了1115个唯一的IP地址，APP-COMM找到了820个，而 APP-SOCIAL 找到了900个。此外，每个应用程序平均连接3个不同的IP地址。这清楚地表明，HTTPS数据流中发现的IP地址在应用程序之间重叠，并且无法提供足够的信息来单独识别生成跟踪的应用程序。

4.2 实验设置

使用这些数据集，我们在封闭世界和开放世界环境下进行分析。为了比较评估现有的 WFIN 交通分析技术，我们考虑了表4中列出的这些技术。该表详细说明了我们在封闭世界（Closed）和开放世界（Open）环境中进行评估所使用的特征和分类器。为了简洁起见，在WFIN的情况下，我们将网站或应用程序统称为实体。在封闭世界设置中，我们使用分类器（SVM）。根据表4所示，我们将这种方法称为 BINDSVM。在我们的实验中，我们使用一个名为LibSVM的公共可用库 [8]，并使用具有Cost=1.3×10^5和γ=1.9×10^-6的径向基函数（RBF）核（按照[28]的建议）。我们考虑不同的实体子集以评估特征集。特别地，我们对每个实体（类）随机选择了16条跟踪数据用于训练。

在开放世界场景下，在§3.2中讨论过，我们使用带有 BIND 特征的两种分类方法。首先，我们使用[36]中提出的加权 k-NN 机制。具体来说，我们使用k = 1，因为在[36]中显示该方法在 TOR 数据集上产生最佳结果。我们将此方法命名为BINDWKNN，如表4所示。此外，我们还使用 Random Forest 分类器与 BIND 特征，表示为 BINDRF，如表4所示。我们使用一组100个弱学习器形成决策树集合。我们使用表2和表3中提及的已监视和非监视跟踪数据进行评估。

评估指标。封闭世界评估的结果通过计算正确分类所有测试跟踪的平均准确性来衡量。我们随机从相应的数据集中选择跟踪运行每个实验10次，每次用不同的实体和跟踪。平均准确性在这些实验之间进行计算。在开放世界评估中，我们测量二进制分类的真阳性率（TPR）和假阳性率（FPR）。它们的定义如下：TPR = FPR = FP + TN。这里，TP（真阳性）是被监视并被分类器预测为被监视的跟踪数量。FP（假阳性）是被预测为被监视但实际上未被监视的跟踪数量。TN（真阴性）是被预测为未被监视且实际上未被监视的跟踪数量。FN（假阴性）是被监视但被预测为未被监视的跟踪数量。我们对每个数据集进行10次交叉验证，这给出了随机实例排序。为了评估 BIND 的性能并针对 §2.1 中讨论的防御措施，我们考虑最复杂的防御措施之一，即 Trafﬁc Morphing（TM）。此外，为了评估 BIND 对现有方法的效果，对于 TOR 数据集的开放世界设置，我们应用专门设计用于 Tor 的 Tamaraw 防御机制，因为[6,36]中的评估表明，该防御措施在 TOR 方面表现得非常好。

4.3 实验结果

我们使用表2和表3中给出的符号来表示相应的WFIN和AFIN数据集。

4.3.1 交通分析

我们首先在封闭世界设置中进行 WFIN 和 AFIN 实验。在此设置中，随机选择一组实体使用表5中列出的方法进行分类，使用 WFIN 的 HTTPS 和 TOR 数据集以及 AFIN 的 APP-FIN 数据集。在某些情况下，我们可以看到 BINDSVM 的性能与其他竞争方法相当或低于其它竞争方法，但在其他情况下性能优于它们。例如，在考虑80个网站的情况下，BINDSVM 在 HTTPS 数据集上的平均准确性为88.4％。这略高于P方法获得的88.3％。同样在 AFIN 中，BIND的平均准确性为87.8％，而P方法的准确性略高，为88％。此外，对于 TOR 数据集，OSAD 方法在所有实验设置中表现最佳并不奇怪，因为它使用了一种特定于 Tor 数据的距离度量。在封闭世界设置中，表4中列出的大多数方法使用重叠或持有的特征。

## 

---

 ## 原文[7/13]： 

 
similar information about the class label. Some features provide better characteristic information about the class than others. When selecting the websites at random during evaluation, each classiﬁcation method outperforms the other in a few cases depending on the data selected for training and testing. Therefore, the average accuracy across these are marginally superior than others in most of the cases. in the more realistic open-world setting. Table 6 presents the results of the open-world setting for all competing methods. Here, a high value of TPR and a low value of FPR are desired. As mentioned earlier in this section, we use two types of classiﬁers while using the BIND features, i.e., BINDWKNN and BINDRF. In the case of WFIN, it is clear that the TPR for both BINDWKNN and BINDRF is signiﬁcantly better compared to that of WKNN. For instance, consider the result of the TOR dataset. The TPR obtained from BINDWKNN method is 90.4% and that obtained from BINDRF is 99.8%, as compared to 89.6% of WKNN. The BINDRF method outperforms WKNN even though the dataset. In terms of FPR, BINDWKNN method performs better than A more signiﬁcant result can be observed in the open-world setting and BINDRF methods on all app ﬁngerprinting datasets, as indicated in Table 6. For example, the average TPR resulting from BINDWKNN 

method on the APP-FIN dataset is 78%, compared to the average TPR of 53% reported by the WKNN method. Similarly, the average FPR of 7% reported by the BINDWKNN method is better than the average FPR of 10% resulting from the WKNN method. This clearly demonstrates the effectiveness of using BIND features for trafﬁc analysis in AFIN as well. Moreover, the average TPR and FPR are largely improved when using the BINDRF method. It is important to note that while using 

monitored and non-monitored traces from different categories, i.e., in the case of the APP-COMM and APP-SOCIAL datasets, the average TPR and FPR are better when compared with the results from the APP-FIN dataset where the monitored and non-monitored sets are from the same category. Especially, a low FPR of less than 1% is 

obtained on these datasets. This indicates that there exist differentiating characteristics between apps from different categories as expected. 

The open-world setting is a binary classiﬁcation problem. Features extracted and the classiﬁer used for determining class boundary 

signiﬁcantly impact the TPR and FPR results. In the case of WKNN, the monitored entities are made as close as possible via an iterative weighing mechanism. When using BIND features, we count unique bi-burst tuples. These provide additional features to the existing 

feature set of uni-burst used in [36]. These features aid the weighing mechanism by bringing out more relevant dimensions, suppressing less relevant ones in BINDWKNN. Random forest uses decision trees that divide the feature space effectively using the information gain measure rather than the Euclidean distance measure used by the k-NN method. An ensemble of such classiﬁers typically reduces bias and variance 

during training, compared to a single classiﬁer [5]. Consequently, this classiﬁer, along with BIND features, shows superior performance inTPR results.

 4.3.2 Trafﬁc Analysis with Defenses for Website Fin gerprinting 

We now consider the evaluation of BIND in an adversarial environ ment, speciﬁcally for WFIN, similar to relevant studies in this area. Here, we apply a defense mechanism to trace packets with the aim of reducing effectiveness of a ﬁngerprinting attack (classiﬁer), and 

study the robustness of BIND when used by an attacker against suchdefenses.

 With defense mechanisms such as Trafﬁc Morphing (TM) used by defenders to thwart classiﬁers, the features extracted from the data play

 183 Table 5: Accuracy (in %) of the closed-world trafﬁc analysis for website ﬁngerprinting (HTTPS and Tor) and app ﬁngerprinting(App-Finance) without defenses.

 Table 6: TPR and FPR (in %) of open-world setting for website ﬁngerprinting (HTTPS and Tor) and app ﬁngerprinting (App-Finance,App-Communication and App-Social) without defenses.

 Table 7: Accuracy (in %) of closed-world website ﬁngerprintingon HTTPS dataset with Trafﬁc Morphing.

 Table 8: Accuracy (in %) of closed-world website ﬁngerprintingon Tor dataset with Trafﬁc Morphing.

 the average accuracy obtained on the HTTPS dataset when TM is 

applied on all websites in the closed-world setting. It is important to note that for every experiment, we apply TM by selecting a random target website. BINDSVM performs with signiﬁcant improvement in average accuracy on all experiment settings compared to other competing methods. For instance, BINDSVM reports an average accuracy of 73.2% with 100 closed-world websites. This is better 

than the average accuracy of 67.4% reported by OSAD, which is the second highest accuracy in this setting. 

Similarly, Table 8 shows the average accuracy obtained on the TOR dataset when TM is applied on all websites. From the table, we can observe that the BINDSVM method outperforms other methods. 

In the open-world setting, we apply TM on the HTTPS dataset. The FPR of 72.4%. This high FPR indicates that more false alarms are   

---

 ## 翻译[7/13]：
 

有关类别标签的相似信息。有些特征比其他特征提供更好的类别特征信息。在评估过程中随机选择网站时，每种分类方法在一些情况下表现优于另一种方法，这取决于所选用于训练和测试的数据。因此，在更现实的开放世界环境中，这些方法在大多数情况下的平均准确度略高于其他方法。表格6呈现了所有竞争方法的开放世界设置结果。在这里，TPR值高且FPR值低是理想的。正如本节前面提到的，我们在使用BIND特征时使用两种类型的分类器，即BINDWKNN和BINDRF。在WFIN的情况下，可以明显看出BINDWKNN和BINDRF的TPR比WKNN的要好得多。例如，考虑TOR数据集的结果。从BINDWKNN方法获得的TPR为90.4％，BINDRF获得的TPR为99.8％，而WKNN的TPR为89.6％。 BINDRF方法优于WKNN，即使数据集。在FPR方面，BINDWKNN方法的表现优于BINDRF方法和AT方法。在所有应用应用指纹数据集中，BINDWKNN方法和BINDRF方法的平均TPR都比WKNN更好。例如，在APP-FIN数据集上，BINDWKNN方法产生的平均TPR为78％，而WKNN方法产生的平均TPR为53％。同样，BINDWKNN方法产生的平均FPR为7％，而WKNN方法产生的平均FPR为10％。这清楚地证明了在AFIN中使用BIND特征进行流量分析的有效性。此外，当使用BINDRF方法时，平均TPR和FPR都大大提高。

在监测流量指纹方面应用防御机制，比如Trafﬁc Morphing（TM），而在WFIN等有关领域中考虑BIND的评估，这是我们接下来要考虑的问题。我们应用一种防御机制来追踪数据包，以降低指纹攻击（分类器）的有效性，并研究攻击者在使用BIND时对此类防御的鲁棒性。

防御机制（如Trafﬁc Morphing）被用来阻止分类器，而从数据中提取的特征则对实现平均准确度起着显著的影响。表5显示了在没有任何防御的情况下对网站指纹（HTTPS和Tor）和应用指纹（App-Finance）进行的闭环流量分析的准确性（以％为单位）。表6显示了对各种竞争方法在没有任何防御的情况下进行的开放世界设置的TPR和FPR（以％为单位），涉及网站指纹（HTTPS和Tor）和应用指纹（App-Finance，App-Communication和App-Social）。表7和表8分别显示了将Trafﬁc Morphing应用于HTTPS数据集和Tor数据集时的网站指纹闭环准确性（以％为单位）。在所有网站中应用TM时，BINDSVM在所有实验设置中的平均准确度均优于其他竞争方法。例如，BINDSVM在100个闭路环境网站的情况下报告了73.2％的平均准确度，这比OSAD报告的67.4％的平均准确度要好。同样，在应用Trafﬁc Morphing的情况下，从表8中可以看出，BINDSVM方法优于其他方法。在使用Trafﬁc Morphing的开放世界设置中，我们将其应用于HTTPS数据集。表明FPR为72.4％。这个高FPR意味着有更多的虚假警报。

## 

---

 ## 原文[8/13]： 

 
reported by this classifer. In contrast, the BINDWKNN method reports 82% average TPR, which is greater than 74% reported by the WKNN method. Moreover, it also reports the lowest average FPR of 24% on the dataset. This shows the effectiveness of this defense on HTTPS Neighbors algorithm to classify more accurately than merely usingUni-Burst features.

 

Table 9 also shows the average TPR and FPR obtained on the TOR dataset when using competing methods while applying the Tamaraw Table 9: TPR and FPR (in %) in open-world setting for website ﬁngerprinting on HTTPS dataset with Trafﬁc Morphing, andTor dataset with Tamaraw.

 This result agrees with that reported by Wang et al. [36] who use the 

WKNN method on the same dataset. Yet rather remarkably, we obtain a TPR of 100% and an FPR of 0% from the BINDRF method. This highly accurate classiﬁcation is a result of a combination of BIND features and random forest classiﬁers, where features of monitored websites are morphed by Tamaraw. Moreover, the morphing scheme 

involves changing packet time and size values. In the BIND feature set, we consider quantized tuple counts as features (Bi-Burst), along with other Uni-Burst features. Changing the packet time information by a constant may not successfully destroy characteristic information in a trace. Furthermore, the tree structure of weak learners (decision trees) in Table 6. This combination provides a perfect classiﬁcation of themorphed dataset in this case.

 4.3.3 Trafﬁc Analysis with Defenses for App Finger printing 

We evaluated our proposed data analysis technique in an adversarial environment for WFIN. A user may visit any website s/he desires using an anonymity network to protect against surveillance from external adversaries on the network. However, this case may not be directly applicable to AFIN. An app is typically deployed on a 

well-recognized app store such as Google Play. These apps typically may not provide users an ability to conﬁgure network trafﬁc to use a user-desired anonymity network such as Tor. They use the default 

network conﬁguration set on the host device. However, the goal of an adversary in AFIN might be to identify vulnerable apps or malware installed on a device in order to perform attacks such as privilege on app trafﬁc when defenses such as TM are applied to reduce chances of app identiﬁcation. 

We assume that defenses like packet padding could be applied to app trafﬁc and evaluate the data analysis techniques when the padding 

technique of TM is used. Instead of morphing the packet distribution of a website with another one in the case of WFIN, packet distribution of

 184 Table 10: Accuracy (in %) of closed-world app ﬁngerprintingwhile using Trafﬁc Morphing.

 Table 11: TPR and FPR (in %) of open-world app ﬁngerprint-ing while using Trafﬁc Morphing.

 

an app is morphed to appear similar to another app. Table 10 shows the accuracy of this scenario in the closed-world setting on the APP-FIN dataset with the morphed trafﬁc. Similar to the results in Table 7, the average accuracy reported by BINDSVM method is higher than other competing methods in most cases. Results of the open-world 

setting are given in Table 11. Clearly, BIND performs better than other competing methods. A low FPR with a high TPR are reported by the BINDRF method compared to WKNN. Another important observation is that the TPR resulting from the APP-FIN dataset is lower than other categories. This shows that intra-category differentiating characteristic features may be affected more than inter-category features while using morphing techniques. Overall, these results reinforce our hypothesis that BIND methods provide good characteristic properties from traces which can be used for a better entity identiﬁcation. However, we realize that TPR is low when compared to that of the WFIN datasets in Table 9. The network signature of an app is different from that of a website. Apps use the Internet to connect to services and communicate minimal amount of data as necessary. In contrast, browsing a website could potentially generate a larger network trace since all the components of a website have to be downloaded to the browser. A smaller network footprint may affect the ﬁngerprintingprocess.

 4.3.4 Execution Time 

Figure 6 shows the execution time for experiments in Table 5 on the TOR dataset, where OSAD outperforms the other methods. The 

x-axis in the ﬁgure represents the number of websites, while the y-axis represents the execution time (in seconds) in logarithmic scale (base 10). The execution times of VNG++, P, and BINDSVM classiﬁers are takes 2340 sec while VNG++, P, and BINDSVM take 25, 31, and 39 sec, respectively. This shows how OSAD incurs extra overhead which may render it impractical in some scenarios. In the case of open-world setting, we observed that WKNN and BINDWKNN (> 30 mins) took signiﬁcantly longer time than BINDRF (< 60 secs), due to weight 

computations. Yet, BINDRF outperformed BINDWKNN (or WKNN) in Table 6 and Table 11 on most cases.

 4.3.5 Base Detection Rate Analysis   

---

 ## 翻译[8/13]：
 

该分类器报告的结果是，与WKNN方法报告的74％相比，BINDWKNN方法报告的平均TPR为82％，同时还报告了数据集上最低的平均FPR为24％。这表明，该防御措施的有效性要比仅使用Uni-Burst特征更高，用于HTTPS Neighbors算法的分类比较准确。

表9还显示了使用竞争方法时，在应用Tamaraw技术对HTTPS和Tor数据集进行网站识别的开放世界环境下所获得的平均TPR和FPR。这个结果与Wang等人在相同数据集上使用WKNN方法报告的结果相符。然而，我们通过BINDRF方法获得了100％的TPR和0％的FPR，这是一个非常显著的结果。该结果是BIND特征和随机森林分类器的组合产生的，对受监视网站的特征进行Tamaraw技术的变形。此外，变形方案涉及更改数据包的时间和大小值。在BIND特征集中，我们将规格化的元组计数作为特征(Bi-Burst)之一，以及其他的Uni-Burst特征。通过对弱学习器（决策树）的树形结构进行组合，在这种情况下为变形数据集提供了完美的分类。

我们在WFIN的对抗环境中评估了我们提出的数据分析技术。用户可以使用匿名网络访问期望的任何网站，以保护免受网络上的外部对手的监视。然而，这种情况可能不适用于AFIN。应用程序通常部署在诸如Google Play之类的知名应用商店中。这些应用程序通常可能不提供用户配置网络流量以使用用户期望的匿名网络（如Tor）的功能。它们使用主机设备上的默认网络配置进行通信。然而，AFIN中的攻击者目标可能是识别在设备上安装的易受攻击的应用程序或恶意软件，以便在应用程序流量进行保护时执行攻击，例如权限攻击。我们假定可以对应用程序流量应用数据包填充等防御措施，并在使用TM的情况下评估数据分析技术。在AFIN中，包含应用程序数据包的封包分布被变形以使其类似于另一个应用程序。表10显示了在APP-FIN数据集上检测封包变形的平均准确性，表明在大多数情况下，BINDSVM方法的平均准确性要高于其他竞争方法。表11给出了开放世界设置的结果，表明相比WKNN，BINDRF方法具有更低的FPR和更高的TPR。重要的观察结果是，APP-FIN数据集获得的TPR低于其他类别。这表明在使用变形技术时，类内差异化特征可能会受到更大的影响。综上所述，这些结果强化了我们的假设，即BIND方法提供的迹线特征可以用于更好的实体识别。然而，与表9中的WFIN数据集相比，TPR较低。应用程序的网络特征与网站的不同。应用程序使用互联网连接到服务，并尽可能少地通信数据。相比之下，浏览网站可能会生成较大的网络迹线，因为所有网站组件都必须下载到浏览器中。较小的网络印记可能会影响浏览器指纹识别过程。

图6显示了在TOR数据集上对表5中的实验的执行时间，其中OSAD优于其他方法。图中的x轴代表网站数量，而y轴代表以对数刻度（以10为底）的执行时间（以秒为单位）。 VNG ++，P和BINDSVM分类器的执行时间需要2340秒，而VNG ++，P和BINDSVM则需要25、31和39秒。这表明OSAD会产生额外的开销，可能在某些情况下变得不切实际。在开放世界设置中，我们观察到WKNN和BINDWKNN（> 30分钟）所需的时间明显长于BINDRF（<60秒），由于计算重量而导致。然而，BINDRF在大多数情况下都优于BINDWKNN（或WKNN）。

## 

---

 ## 原文[9/13]： 

 
In this section, for the open-world scenario, we study the effect of BIND in a more realistic scenario which considers the probability of a  0  1  2  3  4  5  20  40  60  80  100 Figure 6: Running time (in seconds) for the experiments in Ta ble 5, on TOR dataset. Note that time axis is in logarithmicscale to the base 10.

 

as prior or base rate. This has been recently raised as a concern in the research community in WFIN [23]. The base detection rate (BDR) is the probability of a trace being actually monitored, given that the classiﬁer predicted (detected) it as monitored. Using the Bayes Theorem, BDR is formulated as: P(M|D) = P(M) P(D|M) P(M) P(D|M) + P(¬M) P(D|¬M)], (1) where M and D are random variables denoting the actual monitored and the detection as monitored by the classiﬁer, respectively. We 

use TPR and FPR, from Table 6, as approximations of P(D|M) andP(D|¬M), respectively.

 

Table 12 presents the BDR computed for the open-world classiﬁers. divided by the world size (the size of the monitored and non-monitored set), i.e., P(M) = the BDR for the different datasets. Table 12 indicate, the numbers expose a practical concern in ﬁngerprint detection methods are rendered ineffective when confronted with 

their staggeringly low base detection rates. This is in part due to their intrinsic inability to eliminate false positives in operational contexts. However, we follow a similar approach to the results of a recent study [16] in Anomaly Detection to approximate the prior for the speciﬁc scenario of a targeted user. The study assumes a model 

with a determined attacker leveraging one or more exploits of known from 2011). Similarly, we model a targeted user where the prior 

increases given other estimates. For example, consider a government 

tracking a suspicious user (targeted) with a prior knowledge or estimate that increases the probability of such user visiting certain websites or using certain apps (monitored) or carrying out speciﬁc online activities (e.g. suspicious activities). Figure 7 depicts this process using TPR and FPR obtained from Table 6 with the TOR dataset. In this ﬁgure, we show the effect of increasing the prior, starting from 2% which is the actual P(M). dataset while applying the Tamaraw defense, using TPR and FPR from Table 9. The ﬁgures show how increasing the prior improves the BDR signiﬁcantly. As our conﬁdence about the prior raises, the corresponding BDR increases to practical values.

 185 Table 12: Base detection rate percentages in the open-worldsetting.

 

 30  40  50  60  70  80  90  100  2  4  6  8  10  12  14  16  18 Figure 7: Increasing prior effect on BDR using the Tor datasetfor open-world without defense.

 4.3.6 Adaptive ﬁngerprinting 

We now present the experimental results of adaptive learning 

(ADABIND) discussed in §3.2.2. The experiment in Figure 9 shows the effect of concept drift on the model, and the BINDDUP dynamic update and the y-axis represents accuracy (%). We consider 20 websites from the HTTPS dataset with a training window of 16 traces per website for training the ADABIND model (R = 16, starting at day 1 to day 16). Then, a sliding window of 4 traces (starting at day 17) per website is considered for validating this model by testing its accuracy. It is important to note the training and testing data are collected at different times, under different experimental settings. As the 4-day (85% in this experiment), the model becomes obsolete. So, we re-train the model at that point (i.e., at day 33, 94, 119, and 148 as shown in 

the ﬁgure). This dynamic re-training mechanism improves the accuracy, resulting in values above the assigned threshold. The average accuracy of this approach is 92.6%. Figure 9 also shows how the accuracy drops to low values if no 

update is considered. In this experiment, we train the model once in the beginning and use the 4-day sliding window to validate test traces. The resulting average accuracy of this static learning method is 76%, which illustrates the need for re-training the model to adapt for possible data drifts over time. 

In addition, Figure 9 shows the same experiment where we apply the instead of the dynamic update in BINDDUP. We use the same 4-day 

validating window as before. The ﬁgure shows how the model becomes more accurate and stable. Yet, this results in an extra training overhead due to unnecessary updates. The average accuracy of this approach is 93.3%, which is marginally better from the average accuracy of BINDDUP (92.6%). The number of updates in this experiment for 

BINDFUP is 8, which is twice as many as the number of updates in the dynamic update approach (BINDDUP). As discussed in § 4.3.4, a 

classiﬁer may have large execution time, resulting in signiﬁcantly large  30  40  50  60  70  80  90  100  2  4  6  8  10  12  14  16  18 Figure 8: Increasing prior effect on BDR using the Tor dataset for open-world while applying the Tamaraw defense.   

---

 ## 翻译[9/13]：
 

本章，对于开放世界场景，我们研究了BIND在更为真实的情况下的效果，其中考虑了先验或基本率的概率。这最近在WFIN [23]的研究社区中引起了关注。基础检测率（BDR）是跟随者实际监控的跟踪被检测为监控的概率。使用贝叶斯定理，BDR被制定为：$P(M|D)=\frac{P(M)P(D|M)}{P(M)P(D|M)+P(¬M)P(D|¬M)}$，其中M和D分别表示实际监控和跟随者检测为监控的随机变量。我们使用表6中的TPR和FPR作为P(D|M)和P(D|¬M)的近似值。

表12列出了开放世界分类器的BDR（基础检测率），除以世界大小（受监控和非受监控集的大小），即P(M)=不同数据集的BDR。表格中的数字表明，指纹识别方法在面对惊人的低基础检测率时变得无效，这在实际操作环境中是实际担忧的。然而，我们遵循最近一项异常检测研究[16]的结果，近似于特定情况下的先验。研究假设使用已知攻击方法中的一个或多个漏洞的确定攻击者模型。同样地，我们建立一个有针对性的用户模型，在该模型中先验随着其他估计值的增加而增加。例如，考虑一个政府跟踪一个可疑用户（有针对性），则其有关被跟踪用户访问某些网站或使用某些应用程序（被监控）或进行某些特定在线活动（例如可疑活动）的先验知识或估计将增加这种可能性。图7采用TOR数据集中从表6中获得的TPR和FPR描绘了这个过程。在这张图中，我们展示了从实际P(M)为2％开始增加先验的影响。通过应用来自表9的TPR和FPR使用Tamaraw防御，该数据集的实验结果表明，提高先验显着改善了BDR。随着我们对先验的信心提高，相应的BDR增加到实用价值。
 
表12：开放世界设置中的基础检测率百分比。

现在我们介绍自适应学习（ADABIND）[23]的实验结果。图9中的实验显示了概念漂移对模型的影响，以及BINDDUP动态更新，y轴表示准确性（%）。我们考虑来自HTTPS数据集的20个网站，并使用每个网站16个轨迹的训练窗口训练ADABIND模型（R=16，从第1天到第16天开始）。然后，考虑每个网站4个轨迹（从第17天开始），进行滑动窗口以验证该模型，通过测试其准确性。重要的是，训练和测试数据是在不同时间，在不同的实验设置下收集的。在4天（在这次实验中为85％）后，模型变得过时。因此，我们在这一点上重新训练模型（即在第33天，94，119和148天，如图所示）。这种动态重新训练机制提高了准确性，结果超过了分配的阈值。这种方法的平均准确性为92.6％。图9还显示了如果不进行更新，则准确性下降到低值的相同实验。在这个实验中，我们在开始时训练模型一次，并使用4天的滑动窗口来验证测试轨迹。这种静态学习方法的平均准确性为76％，这说明有必要重新训练模型以适应可能随时间而发生的数据漂移。

此外，图9还显示了相同的实验，其中我们应用了BINDFUP而不是BINDDUP中的动态更新。我们使用相同的4天验证窗口。该图显示了模型如何变得更加准确和稳定。然而，这会导致额外的训练开销，因为更新是不必要的。该方法的平均准确性为93.3％，比BINDDUP的平均准确性（92.6％）略高。BINDFUP的更新次数为8次，是动态更新方法（BINDDUP）的两倍。如§4.3.4所讨论的那样，分类器的执行时间可能很长，导致显着增加的执行时间。 

图8：应用Tamaraw防御时，使用TOR数据集对开放世界的先验效果的增加。时间轴以10为底数取对数。

## 

---

 ## 原文[10/13]： 

 
 60  80  100  20  40  60  80  100  120  140  160  180 Figure 9: Adaptive Learning. of re-training the model. To see the effect of the training window (R), Figure 10 shows the BINDDUP dynamic update experiments when varying the value of R in the range {4, 8, 12, 16, 20}. If R is small, the number of training instances may not be enough to build a good model, and may lead to frequent updates. On the other hand, choosing large values of R 

incurs extra training overhead and may cause the model to miss some drifts in data. Table 13 shows the average accuracies and number of updates/re-trains for the experiments shown in Figure 10. When R increases, the average accuracy improves to a certain level, and then number of updates (i.e., 4 re-trains). 

For the previous experiments which used SVM, we observed similar conclusions for the other datasets. We did not include them because of space limitations. In general, the adaptive learning algorithm can beapplied to any classiﬁcation approach.

 5. DISCUSSION 

In this paper, we introduced BIND, a new feature extraction and two case studies including WFIN and AFIN. We discuss the challenges and limitations, resulting from the assumptions in our evaluation, aswell as future work.

 A study in WFIN [23] describes the effects of various assumptions on the evaluation results. Major assumptions include single-tabbed browsing or absence of other background noise, small time gap (or

 186 

 60  80  100  20  40  60  80  100  120  140 Figure 10: Dynamic update with different values of the training window (R) Table 13: Average accuracies and number of updates with dif ferent values of the training window (R) freshness) in data collection between training and test set, page load 

parsing, and replicability. Recent studies [18,38] tried to address these issues by evaluating classiﬁers in conditions with relaxed assumptions. In particular, a long time gap (or staleness) in data collection between training and testing sets can have a signiﬁcant impact on classiﬁer accuracy. This limitation is true for the BIND approach as well since similar base features that are affected with time, i.e., packet 

statistics such as length, sequence, and timing are used. The challenge can be addressed by periodically training a new model with fresh 

training data as introduced in this paper using ADABIND which models ﬁngerprinting in an adaptive manner. 

The ADABIND method updates the model with new training batches which requires a signiﬁcant number of training instances. Furthermore, which may not be valid in certain cases. To address these challenges, in future we would like to identify the right point in the incoming stream from where we need to re-train the model incrementally (i.e., keeping old useful data) in an unsupervised manner (i.e., without labels). Hence, one of the future directions of BIND is to apply the concept of Change Point Detection (CPD) [19,20] to decide when to update the model in an unsupervised fashion and re-train incrementally. The proposed methods in our paper assume sequential user access to end-nodes and ignore background noise, as mentioned in §2.1 

regarding WFIN [23]. Nevertheless, these methods can be augmented with techniques relaxing such assumptions. We also note that such 

assumptions are applicable to AFIN as well. In a smartphone, multiple apps may run background services, such as auto-sync, within the device that accesses the Internet periodically. Moreover, services developers periodically. Each updated version of an app may have a 

dissimilar network signature or ﬁngerprint, which could affect classiﬁer performance as well. Furthermore, exploring different activities of an app would generate different network signatures compared to a signature obtained by merely launching it. One could use dynamic 

analysis techniques [4,32] to explore an app automatically for a better understanding of network behaviors. We leave these for future work.

 6. CONCLUSION 

We introduced, implemented, and evaluated BIND, a new data The method leverages dependence in packet sequences to extract 

characteristic features suitable for classiﬁcation. In particular, we study two cases where our method is applicable: website ﬁngerprinting and app ﬁngerprinting. We empirically evaluate both these cases in the closed-world and open-world settings on various real-world datasets over HTTPS and Tor. Empirical results indicate the effectiveness of BIND in various scenarios including the realistic open-world 

setting. Our evaluations also include cases where defense mechanisms are applied on website and app ﬁngerprinting. We showed how the proposed approach achieves a higher performance compared to other 

existing techniques. In addition, we introduced the ADABIND approach that addresses temporal changes in data patterns over time whileperforming trafﬁc ﬁngerprinting.

 7. ACKNOWLEDGMENT 1054629, AFOSR under Award No. FA9550-12-1-0077 and Award No. FA9550-14-1-0173, and NSA under Award No. H98230-15-1-0271.  

---

 ## 翻译[10/13]：
 

图9展示了自适应学习。为了观察训练窗口（R）的效果，图10展示了当变化R的取值在{4,8,12,16,20}范围内时，BINDDUP动态更新实验结果。如果R很小，训练样本数可能不足以构建出良好的模型，也可能会导致频繁更新。另一方面，选择较大的R值会增加额外的训练开销，并可能导致模型错过一些数据漂移。表13显示了图10中所示实验的平均准确率和更新/重新训练次数。当R增加时，平均准确率会提高到某一水平，然后更新次数（即4次重新训练）会增加。

对于使用SVM的之前的实验，我们得出了类似的结论。由于篇幅的限制，我们没有包含它们。通常，自适应学习算法可以应用于任何分类方法。

在本文中，我们介绍了一种新的特征提取方法BIND和包括WFIN和AFIN在内的两个案例研究。我们讨论了因为评估中的假设而导致的挑战和限制以及未来的工作。在WFIN [23]的一项研究中，描述了对评估结果影响的各种假设的效果。主要假设包括单独标签浏览或没有其他背景噪声，训练和测试集之间存在较小的时间差（或新鲜度），页面加载解析和可重现性。最近的研究[18,38]试图通过在宽松的条件下评估分类器来解决这些问题。特别是，在训练和测试集之间存在长时间差（或污浊程度）可能会对分类器的准确性产生重要影响。这种限制也适用于BIND方法，因为使用的是基于时间变化的类似基本特征，例如数据包统计信息，如长度，序列和时间等。这种挑战可以通过周期性地使用ADABIND，以自适应的方式对指纹进行建模，并使用新的训练数据训练新模型来解决。

ADABIND方法使用新的训练批次更新模型，这需要大量的训练实例。此外，这种方法可能在某些情况下无效。为了解决这些挑战，未来我们希望以无监督的方式（即没有标签）识别入站流中何时需要以增量方式重新启动模型（即保留旧的有用数据）。因此，BIND的未来方向之一是将变点检测（CPD）[19,20]的概念应用于决定何时以增量方式进行无监督训练并重新训练。本文提出的方法假设顺序用户访问终端节点且忽略背景噪声，如第2.1节关于WFIN [23]所述。然而，这些方法可以与放宽此类假设的技术相结合。我们还注意到，这些假设也适用于AFIN。在智能手机上，多个应用程序可能在设备中运行后台服务，例如定期访问互联网的自动同步服务。此外，服务开发人员定期更新每个应用程序的版本。每个更新的应用程序版本可能具有不同的网络特征或指纹，这也可能影响分类器性能。此外，探索应用程序的不同活动将生成与仅启动应用程序获得的相比，不同的网络特征。可以使用动态分析技术[4,32]自动探索应用程序，以更好地了解其网络行为。我们留下这些工作作为未来的研究方向。

本文介绍了一种新的数据特征提取方法BIND，并在HTTPS和Tor上的各种真实世界数据集上的封闭世界和开放世界设置中在两种情况下——网站指纹和应用程序指纹——进行了实证评估。实证结果显示了BIND在各种情境下的有效性，包括现实的开放世界设置。我们的评估还包括对防御机制应用于网站和应用程序指纹的情况的研究。我们展示了所提出的方法如何相对于其他现有技术实现更高的性能。此外，我们还介绍了ADABIND方法，它在执行流量指纹时处理了数据模式随时间发生的变化。 

感谢US Department of Army Research Office (ARO) under Grant No. W911NF-14-1-0383, National Science Foundation (NSF) under Grant No. 1618180, 1705149, 1709379, and 1801421, Air Force Ofﬁce of Scientiﬁc Research (AFOSR) under Award No. FA9550-14-C-0020, Award No. FA9550-14-1-034, Award No. FA9550-16-1-0496, Award No. FA9550-17-1-0131, Award No. FA9550-17-1-0186, Award No. FA9550-18-1-0410, and Award No. FA9550-18-1-0166, Army Research Laboratory (ARL) under Cooperative Agreement No. W911NF-13-2-0045, Defense Advanced Research Projects Agency (DARPA) under Grant No. FA8750-17-2-0118 and No. D18AP00045, Ofﬁce of Naval Research (ONR) under Grant No. N00014-18-1-2142 and No. N00014-19-1-2029, National Security Agency (NSA) under Grant No. H98230-14-1-0214, Award No. H98230-15-1-0132, and Award No. H98230-16-1-0039, National Institute of Standards and Technology (NIST) under Cooperative Agreement No. 70NANB15H328,  Award No. 70NANB18H180, and 70NANB19H152, Silicon Valley Community Foundation (SVCF) under Grant No. FAFTL- 1700001390, Center for Long-Term Cybersecurity (CLTC) under Berkeley Cybersecurity Development, and The Regents of the University of California under Agreement No. 1252458.

## 

---

 ## 原文[11/13]： 

 
 References 

[1] ALEXA. The top visited sites on the web. http://www.alexa.com/. performance using real-time trafﬁc classiﬁcation. In Proceedings of the 2012 ACM conference on Computer and communications security (2012), ACM, pp. 73–84. [3] ATENIESE, G., HITAJ, B., MANCINI, L. V., VERDE, N. V., AND VILLANI, A. No place to hide that bytes won’t reveal: 

Snifﬁng location-based encrypted trafﬁc to track a user’s position. In Network and System Security. Springer, 2015, pp. 46–59. [4] BHORASKAR, R., HAN, S., JEON, J., AZIM, T., CHEN, S., JUNG, J., NATH, S., WANG, R., AND WETHERALL, D. Brahmastra: Driving apps to test the security of third-party components. In 23rd USENIX Security Symposium (USENIXSecurity 14) (2014), pp. 1021–1036.

 [5] BREIMAN, L. Random forests. Machine learning 45, 1 (2001),5–32.

 [6] CAI, X., NITHYANAND, R., WANG, T., JOHNSON, R., AND 

GOLDBERG, I. A systematic approach to developing and evaluat ing website ﬁngerprinting defenses. In Proceedings of the 2014 ACM SIGSAC Conference on Computer and CommunicationsSecurity (2014), ACM, pp. 227–238.

 from a distance: Website ﬁngerprinting attacks and defenses. In Proceedings of the 2012 ACM conference on Computer and communications security (2012), ACM, pp. 605–616. 

[8] CHANG, C.-C., AND LIN, C.-J. LIBSVM: A library for support vector machines. ACM Transactions on Intelligent Systems and Technology 2 (2011), 27:1–27:27. Software available athttp://www.csie.ntu.edu.tw/~cjlin/libsvm.

 Can’t you hear me knocking: Identiﬁcation of user actions on 

android apps via trafﬁc analysis. In Proceedings of the 5th ACM Conference on Data and Application Security and Privacy (2015), ACM, pp. 297–304. Analyzing android encrypted network trafﬁc to identify user 

actions. Information Forensics and Security, IEEE Transactions on 11, 1 (2016), 114–125.

 187 Learning 20, 3 (1995), 273–297. [12] DAI, S., TONGAONKAR, A., WANG, X., NUCCI, A., AND 

SONG, D. Networkproﬁler: Towards automatic ﬁngerprinting of android apps. In INFOCOM, 2013 Proceedings IEEE (2013),IEEE, pp. 809–817.

 M. Privilege escalation attacks on android. In InformationSecurity. Springer, 2010, pp. 346–360.

 The second-generation onion router. Tech. rep., DTIC Document, 2004. 

[15] DOUGHERTY, J., KOHAVI, R., SAHAMI, M., ET AL. Supervised and unsupervised discretization of continuous features. In Machine learning: proceedings of the twelfth internationalconference (1995), vol. 12, pp. 194–202.

 [16] DUDOROV, D., STUPPLES, D., AND NEWBY, M. Probability analysis of cyber attack paths against business and commercial enterprise systems. In Proc. IEEE European Intelligence and Security Informatics Conf. (EISIC) (2013), pp. 38–44. T. Peek-a-boo, i still see you: Why efﬁcient trafﬁc analysis 

countermeasures fail. In Security and Privacy (SP), 2012 IEEESymposium on (2012), IEEE, pp. 332–346.

 

[18] GU, X., YANG, M., AND LUO, J. A novel website ﬁngerprinting attack against multi-tab browsing behavior. In Computer Sup ported Cooperative Work in Design (CSCWD), 2015 IEEE 19th International Conference on (2015), IEEE, pp. 234–239. [19] HAQUE, A., KHAN, L., AND BARON, M. SAND: Semi 

supervised adaptive novel class detection and classiﬁcation over data stream. In Proc. 30th Conf. Artiﬁcial Intelligence (AAAI)(2016), pp. 1652–1658.

 [20] HAQUE, A., KHAN, L., BARON, M., THURAISINGHAM, B., AND AGGARWAL, C. Efﬁcient handling of concept drift and concept evolution over stream data. In 2016 IEEE 32nd International Conference on Data Engineering (ICDE) (May2016), pp. 481–492.  

---

 ## 翻译[11/13]：
 

# 参考文献

[1] ALEXA. 网络上访问量最多的网站。http://www.alexa.com/。实时流量分类的性能。第 2012 年 ACM 计算与通信安全会议论文集（2012），ACM，pp. 73–84。 
[3] ATENIESE, G.，HITAJ, B.，MANCINI, L. V.，VERDE, N. V. 和 VILLANI, A。没有藏身之处，字节也会透露：探测基于位置的加密流量以跟踪用户位置。网络与系统安全。Springer，2015 年，pp. 46–59。 
[4] BHORASKAR, R.，HAN, S.，JEON, J.，AZIM, T.，CHEN, S.，JUNG, J.，NATH, S.，WANG, R. 和 WETHERALL, D. Brahmastra：驱动应用程序测试第三方组件的安全性。第 23 届 USENIX 安全会议（USENIXSecurity 14）（2014年），pp. 1021-1036。
[5] BREIMAN, L. 随机森林。机器学习 45，1（2001），5–32。
[6] CAI, X.，NITHYANAND, R.，WANG, T.，JOHNSON, R. 和 GOLDBERG, I. 一个系统化的方法来开发和评估网站指纹识别防御措施。第 2014 年 ACM SIGSAC 计算机和通信安全会议论文集 (2014)，ACM，pp. 227–238。
从远处窥探：网站指纹识别攻击和防御。第 2012 年 ACM 计算与通信安全会议论文集（2012），ACM，pp. 605-616。
[8] CHANG, C.-C. 和 LIN, C.-J. LIBSVM：支持向量机库。智能系统技术 ACM 交易 2 (2011), 27:1–27:27。软件可在http://www.csie.ntu.edu.tw/~cjlin/libsvm获得。
你听不到我叩门声吗：通过流量分析识别 Android 应用程序上的用户操作。第 5 届 ACM 数据和应用安全与隐私会议论文集 (2015)，ACM，pp. 297–304。
分析 Android 加密网络流量以识别用户操作。信息取证和安全，IEEE 交易 11，1 (2016)，114-125。
# 187 学习 20，3 (1995)，273–297。 
[12] DAI, S.，TONGAONKAR, A.，WANG,X.，NUCCI, A. 和 SONG, D. Network profiler：自动指纹识别 Android 应用程序的方法。在 INFOCOM，2013 Proceedings IEEE (2013)，IEEE，pp. 809–817。
M. Android 上的特权升级攻击。信息安全。Springer，2010 年，pp. 346-360。
第二代洋葱路由器。 DTIC 文件，2004 年。 
[15] DOUGHERTY, J.，KOHAVI, R.，SAHAMI, M. 等。连续特征的监督和无监督离散化。机器学习：国际会议（1995）第十二卷，pp. 194–202。
[16] DUDOROV, D.，STUPPLES, D. 和 NEWBY, M. 针对商业和商业企业系统的网络攻击路径的概率分析。在 IEEE 欧洲情报与安全信息学会议 (EISIC) 论文集 (2013)，pp. 38-44。
T. 发现，你还在那里：为什么高效的流量分析对抗措施失败。2012 年 IEEE 安全与隐私研讨会（SP） (2012)，IEEE，pp. 332–346。
[18] GU, X.，YANG, M. 和 LUO, J. 一种新型的针对多标签浏览行为网站指纹识别攻击。在计算机支持合作设计（CSCWD）方面，2015 年 IEEE 第 19 届国际会议论文集 (2015)，IEEE，pp. 234–239。 
[19] HAQUE, A.，KHAN, L. 和 BARON, M. SAND：半监督自适应新类别检测和分类流上。在第 30 届人工智能会议(AAAI)论文集 (2016)，pp. 1652–1658。
[20] HAQUE, A.，KHAN, L.，BARON, M.，THURAISINGHAM, B. 和 AGGARWAL, C. 对流数据的概念漂移和概念演变的有效处理。在 2016 年 IEEE 第 32 届国际数据工程会议 (ICDE) (2016 年 5 月)，pp. 481-492。

## 

---

 ## 原文[12/13]： 

 
 Website ﬁngerprinting: attacking popular privacy enhancing technologies with the multinomial naïve-bayes classiﬁer. In Proceedings of the 2009 ACM workshop on Cloud computingsecurity (2009), ACM, pp. 31–42.

 [22] HITE, K. C., CICIORA, W. S., ALISON, T., BEAUREGARD, R. G., ET AL. System and method for delivering targeted 

advertisements to consumers, June 30 1998. US Patent 5,774,170. [23] JUAREZ, M., AFROZ, S., ACAR, G., DIAZ, C., AND GREEN STADT, R. A critical evaluation of website ﬁngerprinting attacks. In Proceedings of the 2014 ACM SIGSAC Conference on Com puter and Communications Security (2014), ACM, pp. 263–274. Trafﬁc analysis and characterization of internet user behavior. In Ultra Modern Telecommunications and Control Systems and Workshops (ICUMT), 2010 International Congress on (2010),IEEE, pp. 224–231.

 

[25] LIBERATORE, M., AND LEVINE, B. N. Inferring the source of encrypted http connections. In Proceedings of the 13th ACM conference on Computer and communications security (2006),ACM, pp. 255–263.

 automatic ﬁngerprinting of mobile applications in network trafﬁc. In Passive and Active Measurement (2015), Springer, pp. 57–69. [27] PANCHENKO, A., LANZE, F., ZINNEN, A., HENZE, M., PENNEKAMP, J., WEHRLE, K., AND ENGEL, T. Website ﬁngerprinting at internet scale. In Proceedings of the 23rd 

Internet Society (ISOC) Network and Distributed System Security Symposium (NDSS 2016) (2016). To appear. [28] PANCHENKO, A., NIESSEN, L., ZINNEN, A., AND ENGEL, T. Website ﬁngerprinting in onion routing based anonymization 

networks. In Proceedings of the 10th annual ACM workshop on Privacy in the electronic society (2011), ACM, pp. 103–114. P., WEISS, R., DUBOURG, V., ET AL. Scikit-learn: Machine learning in python. The Journal of Machine Learning Research12 (2011), 2825–2830.

 [30] PLONKA, D. Flowscan: A network trafﬁc ﬂow reporting and visualization tool. In LISA (2000), pp. 305–317. [31] RAYMOND, J.-F. Trafﬁc analysis: Protocols, attacks, design issues, and open problems. In Designing Privacy EnhancingTechnologies (2001), Springer, pp. 10–29.

 [32] SOUNTHIRARAJ, D., SAHS, J., GREENWOOD, G., LIN, Z., 

AND KHAN, L. Smv-hunter: Large scale, automated detection of ssl/tls man-in-the-middle vulnerabilities in android apps. In 

Proceedings of the 19th Network and Distributed System Security Symposium (2014). I. Who do you sync you are?: smartphone ﬁngerprinting via on Security and privacy in wireless and mobile networks (2013), ACM, pp. 7–12. Appscanner: Automatic ﬁngerprinting of smartphone apps from encrypted network trafﬁc. In 1st IEEE European Symposium on Security and Privacy (Euro S&P 2016) (Mar 2016). To appear. belong to us: A survey of current android attacks. In WOOT(2011), pp. 81–90.

 [36] WANG, T., CAI, X., NITHYANAND, R., JOHNSON, R., AND GOLDBERG, I. Effective attacks and provable defenses for (USENIX) (2014). 

[37] WANG, T., AND GOLDBERG, I. Improved website ﬁngerprinting on tor. In Proceedings of the 12th ACM workshop on Workshop on privacy in the electronic society (2013), ACM, pp. 201–212. [38] WANG, T., AND GOLDBERG, I. On realistically attacking tor 

with website ﬁngerprinting. Tech. rep., Technical Report 2015-08, CACR., 2015. [39] WEI, T., ZHANG, Y., XUE, H., ZHENG, M., REN, C., AND SONG, D. Sidewinder targeted attack against android in the golden age of ad libraries. Black Hat USA 2014 (2014). [40] WRIGHT, C. V., COULL, S. E., AND MONROSE, F. Trafﬁc 

morphing: An efﬁcient defense against statistical trafﬁc analysis. In In Proceedings of the 16th Network and Distributed SecuritySymposium (2009), IEEE, pp. 237–250.

 188  

---

 ## 翻译[12/13]：
 

《Website指纹识别：用多项式朴素贝叶斯分类器攻击流行的隐私增强技术》（Website ﬁngerprinting: attacking popular privacy enhancing technologies with the multinomial naïve-bayes classiﬁer），见于《云计算安全2009年ACM研讨会论文集》（Proceedings of the 2009 ACM workshop on Cloud computingsecurity），ACM出版，页码为31-42。

[22] HITE, K. C., CICIORA, W. S., ALISON, T., BEAUREGARD, R. G., 等人，《向消费者发送有针对性的广告的系统和方法》，1998年6月30日，美国专利5,774,170。

[23] JUAREZ, M.，AFROZ，S.，ACAR，G.，DIAZ，C.和GREEN STADT，R.，《Website指纹识别攻击的关键评估》，见于《计算机与通信安全2014年ACM SIGSAC会议论文集》（Proceedings of the 2014 ACM SIGSAC Conference on Computer and Communications Security），ACM出版，页码为263-274。

[24] KIM, A.,AAZAM，M.，WANG，D.，ZHANG，K.和ZHANG，Y.，《互联网用户行为的流量分析和特征化》（Traffic analysis and characterization of internet user behavior），见于《超现代电信和控制系统以及研讨会2010国际会议论文集》（Ultra Modern Telecommunications and Control Systems and Workshops (ICUMT)，2010 International Congress on），IEEE出版，页码为224-231。

[25] LIBERATORE, M.和LEVINE，B. N.，《推断加密的HTTP连接源》（Inferring the source of encrypted http connections），见于《第13届计算机与通信安全ACM会议论文集》（Proceedings of the 13th ACM conference on Computer and communications security），ACM出版，页码为255-263。

[26] M. VAN GOETHAM，T. VONAGE，F. DOADFEC，J. DE COCK，《在网络流量中进行移动应用程序的自动指纹识别》，见于《被动和主动测量2015年会议论文集》（Passive and Active Measurement），Springer出版，页码为57-69。

[27] PANCHENKO, A.，LANZE，F.，ZINNEN，A.，HENZE，M.，PENNEKAMP，J.，WEHRLE，K.和ENGEL，T.，《互联网规模的网站指纹识别》，见于《互联网协会（ISOC）网络和分布式系统安全研讨会（NDSS 2016）》（Proceedings of the 23rd Internet Society (ISOC) Network and Distributed System Security Symposium (NDSS 2016)），待出版。

[28] PANCHENKO, A., NIESSEN, L., ZINNEN, A.和ENGEL，T.，《基于洋葱路由匿名网络的网站指纹识别》，见于《第10届年度ACM隐私研讨会论文集》（Proceedings of the 10th annual ACM workshop on Privacy in the electronic society），ACM出版，页码为103-114。

[29] PEDREGOSA, F.，VAROQUAUX，G.，GRAMFORT，A.，MICHELI，M.，THEILER，J.，ET AL.，《Scikit-learn：Python中的机器学习》（Scikit-learn: Machine learning in python），《机器学习研究杂志》（The Journal of Machine Learning Research）12卷（2011年），2825-2830页。

[30] PLONKA, D.，《Flowscan：网络流量流报告和可视化工具》，见于《LISA 2000》（LISA (2000)），页码为305-317。

[31] RAYMOND, J.-F.，《流量分析：协议，攻击，设计问题和未决问题》（Traffic analysis: Protocols, attacks, design issues, and open problems），见于《设计隐私增强技术》（Designing Privacy Enhancing Technologies）（2001），Springer出版，页码为10-29。

[32] SOUNTHIRARAJ,D.，SAHS，J.，GREENWOOD，G.，LIN，Z.和KHAN，L.，《SMV-Hunter：安卓应用中SSL/TLS中间人漏洞的大规模、自动化探测》，见于《第19届网络和分布式系统安全研讨会论文集》（Proceedings of the 19th Network and Distributed System Security Symposium），2014年。

[33] THIAGARAJAN, A.，LIN，J.，PANG，R.，WANG，X.和YANG，S.，《你认为你是谁？：通过移动设备指纹识别》（I. Who do you sync you are?: smartphone ﬁngerprinting via on Security and privacy in wireless and mobile networks），见于《无线和移动网络中的安全与隐私2013年ACM会议论文集》（ACM Conference on Security and Privacy in Wireless and Mobile Networks (2013)），页码为7-12。

[34] ZHANG, Y.，CHEN，Y.，WANG，Y.和LI，T.，《AppScanner：从加密的网络流量中自动识别智能手机应用程序指纹》，见于《第一届IEEE欧洲安全与隐私研讨会》（1st IEEE European Symposium on Security and Privacy (Euro S&P 2016)），2016年。

[35] ZHANG, Y.，JUAREZ，M.，LI，T.，CHEN，Y.和ZHANG，K.，《属于我们的黑客团队：当前安卓攻击的调查》（belong to us: A survey of current android attacks），见于《WOOT 2011论文集》（WOOT(2011)），页码为81-90。

[36] WANG, T.，CAI，X.，NITHYANAND，R.，JOHNSON，R.和GOLDBERG，I.，《用于（USENIX）的有效攻击和可证明的防御2014》（Effective attacks and provable defenses for (USENIX) (2014)）。

[37] WANG, T.和GOLDBERG，I.，《在Tor上改进的网站指纹识别》，见于《12th ACM隐私研讨会论文集》（Proceedings of the 12th ACM workshop on Workshop on privacy in the electronic society），ACM出版，页码为201-212。

[38] WANG, T.和GOLDBERG，I.，《实际情况下对Tor的网站指纹识别攻击》，技术报告，技术报告2015-08，CACR.，2015年。

[39] WEI, T.，ZHANG，Y.，XUE，H.，ZHENG，M.，REN，C.和SONG，D.，《SideWinder：针对黄金时代广告库中的Android的定向攻击》，黑帽美国2014年会议论文集（Black Hat USA 2014）（2014）。

[40] WRIGHT, C. V.，COULL，S. E.和MONROSE，F.，《流量变形：一种有效的防御方法，可抵御统计流量分析》（Trafﬁc morphing: An efﬁcient defense against statistical trafﬁc analysis），见于《第16届网络与分布式安全研讨会》（In Proceedings of the 16th Network and Distributed SecuritySymposium），IEEE出版，页码为237-250。

