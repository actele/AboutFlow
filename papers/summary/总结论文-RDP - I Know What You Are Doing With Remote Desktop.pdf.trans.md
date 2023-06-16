# RDP - I Know What You Are Doing With Remote Desktop 分析报告
## 一、论文概况

---



### 标题
I Know What You Are Doing With Remote Desktop

### 收录会议或期刊
Unknown

### 作者
Minghao Jiang1,2, Gaopeng Gou1,2, Junzheng Shi1,2, Gang Xiong1,2

### 摘要
Abstract—Remote desktop enables users to remotely access their computers via the Internet, which is widely used as a basic tool in areas such as remote work, remote assistance and remote administration. However, existing remote desktop is designed to work in the mode of updating user’s real-time command and remote screen’s state interactively for a better user experience, such working mode may cause serious side-channel information leakage problem in spite of encryption of the trafﬁc, as revealed in this paper. We carry out an experimental research to assess the side-channel information leakage of six most popular remote desktop softwares in Windows 10 & 7 platforms: Anydesk, ConnectWise, MicroRDS, RealVNC, Teamviewer, and Zoho Assist. With the help of machine learning techniques including logistic regression, support vector machine, gradient boosting decision tree, random forest as well as statistic features of ﬂow burst, we observe that an adversary can excellently uncover (top at 99.26% TPR, 0.01% FPR) what the user is doing with remote desktop, including inputting sensitive information (password, personal identiﬁcation number), viewing sensitive and conﬁdential documents (tax reports, corporate information), and even conducting malicious activity (launching an exploit or transferring a ﬁle to a remote server). The results highlight the severity of side-channel information leaks on remote desktop softwares for both personal and corporate users. Finally, we propose a general framework for mitigating the side-channel information leakage based on trafﬁc encryption, user situation recognition, and dynamic switching of interaction mode.

### 编号
Unknown

### 作者邮箱
{jiangminghao, gougaopeng, shijunzheng, xionggang}@iie.ac.cn

#### 翻译摘要
远程桌面使用户通过互联网远程访问其计算机，这被广泛应用于远程工作、远程协助和远程管理等领域的基本工具。然而，现有的远程桌面被设计为以交互方式更新用户的实时命令和远程屏幕状态以提供更好的用户体验。尽管加密了流量，但这种工作方式可能会导致严重的旁道信息泄露问题，本文揭示了这一点。我们开展了实验研究，评估了Windows 10和7平台上六种最流行的远程桌面软件的旁道信息泄漏情况：Anydesk、ConnectWise、MicroRDS、RealVNC、Teamviewer和Zoho Assist。借助包括逻辑回归、支持向量机、梯度提升决策树、随机森林以及流量突发统计特征等机器学习技术，我们发现对手能够极好地揭示（TPR 为 99.26%，FPR为0.01%），用户在使用远程桌面时正在进行的活动，包括输入敏感信息（密码、个人识别号码）、查看敏感和机密文档（税务报告、企业信息）甚至进行恶意活动（启动漏洞或将文件传输到远程服务器）。结果突显了远程桌面软件对个人和企业用户侧面信息泄漏严重性。最后，我们提出了基于流量加密、用户情况识别和交互方式动态切换的旁道信息泄漏缓解的通用框架。

---



## 二、论文翻译



## 

---

 ## 原文[0/6]： 

 

 Minghao Jiang1,2, Gaopeng Gou1,2, Junzheng Shi1,2, Gang Xiong1,2 

1Institute of Information Engineering,Chinese Academy of Sciences, Beijing, China 2School of Cyber Security, University of Chinese Academy of Sciences, Beijing, China {jiangminghao, gougaopeng, shijunzheng, xionggang}@iie.ac.cn Remote Desktop has become a basic technique to control a computer remotely by using another device via the internet, it’s popular with the areas, i.e., remote work, remote assistance, remote administration. This need arises as cloud computation has been widely used [1] and telework has been more and more common recently. According to [2], about 3.7 million employees work from home at least half the time. The diversity and low cost of mature remote desktop software such as Teamviewer [3] or RealVNC [4] are also crucial for the pop ularity of remote desktop. In the scene of cloud computation’ infrastructure as a service, cloud administrators use remote control software to control many headless computers while cloud users also use remote desktop to access their subscribed cloud resources and deploy their proprietary applications onthem [5].

 A typical remote desktop software captures the control information such as mouse clicks and keyboard hits from the client operated by a user and sends them to the remote computer. The remote executes the control commands and then feedbacks the changes of the screen to the client interactively. This real-time interactive work mode produces excellent user experience, but it also leads to serious side-channel privacy leakage as this paper displayed. We ﬁnd that the behavior characteristic of trafﬁc might be greatly distinctive when a user performs different operations by remote desktop software, as intuitively illustrated in Fig 1. A user’s activity privacy is sensitive and personal. Given that an adversary learns a user’s daily activities pattern and commonly used softwares, he could perform an advanced persistent threat (APT) attack on the user much more smoothly. For example, after knowing a user often edits ﬁles with Microsoft ofﬁce word 2007 the adversary can easier try to perform remote execute code vulnerability(i.e. CVE-2018-08511) attack on him. Leakage of teleworker’s daily activity pattern to the opponent may pose economic losses in the circumstance of business competition turns out to be another example. We believe that having a correct understanding of remote desktop’s privacy security hascurrent signiﬁcance.

 There are lots of related work both on side-channel infor mation leakage of encrypted trafﬁc [6]–[16] and encrypted trafﬁc classiﬁcation [17]; but it has seldom been addressed in remote desktop scenario except [18]. [18] focused on roughly distinguishing between voice conferences, video conferences, text chat, ﬁle transfers and normal remote sessions encrypted trafﬁc of TeamViewer. However, these ﬁve actions lie outside the area of typically remote control and the attention were not about side-channel information leakage. What differs our work from [18] is that we perform an investigation on the much more sensitive daily activities such as reading a document or editing with Ofﬁce Word when a user controls the remote. Our investigation consists of predeﬁning ﬁve kinds of daily activities on six most popular remote desktop softwares, col lecting the packet length or arrived time information only and employing available machine learning classiﬁers to determine whether an adversary can tell trafﬁc attached to different activities apart in the perspective of side-channel information leakage. Furthermore, we also mount deeper research to see if an adversary can even detect what kind of speciﬁc tool is used by a user on the channel when he edits. Our contributions in this paper can be brieﬂy summarized as follows: • We systematically inspect the ﬁne-grained side-channel information leakage problem when a user controls a 978-1-7281-1025-7/19/$31.00 ©2019 IEEE remote device with remote desktop softwares. Our result reveals that all of the six most popular and state-of-the art remote desktop softwares we analyzed have the risk of leaking user’s privacy information of rough and even ﬁne-grained activities. Both users and providers of remote desktop shall pay much more attention to such seriousprivacy leakage problem.  

---

 ## 翻译[0/6]：
 

江明浩1,2, 苟高鹏1,2, 史俊峥1,2, 熊刚1,2 

1中国科学院信息工程研究所，北京，中国 2中国科学院大学网络空间安全学院，北京，中国 {jiangminghao, gougaopeng, shijunzheng, xionggang}@iie.ac.cn

远程桌面已成为一种通过互联网使用另一设备远程控制计算机的基本技术，广泛应用于远程工作、远程协助和远程管理等领域。随着云计算的广泛应用[1]和远程工作变得越来越普遍，这种需求逐渐增多[2]，约370万员工至少有一半时间在家工作。诸如Teamviewer [3]或RealVNC [4]等成熟的远程桌面软件的多样性和低成本也是远程桌面流行的关键因素。在基础设施即服务的云计算场景中，云管理员使用远程控制软件来控制许多无头计算机，而云用户也使用远程桌面来访问他们订阅的云资源，并在上面部署其专有的应用程序[5]。

典型的远程桌面软件通过从用户操作的客户端捕获控制信息，例如鼠标点击和键盘触发，然后将它们发送到远程计算机。远程执行控制命令，然后交互式地将屏幕的变化反馈给客户端。这种实时交互工作模式产生了出色的用户体验，但也会导致严重的侧信道隐私泄露，正如本文所展示的。我们发现，当用户通过远程桌面软件执行不同操作时，流量的行为特征可能会极大地不同，在图1所直观说明。用户的活动隐私是敏感和个人的。假设对手学习了用户的日常活动模式和常用软件，他可以更加顺利地对用户进行高级持续性攻击（APT）。例如，了解用户经常使用Microsoft Office Word 2007编辑文件后，对手可以更容易地试图对他进行远程执行代码漏洞（即CVE-2018-08511）攻击。向对手泄漏远程工作者的日常活动模式可能在商业竞争的情况下造成经济损失。我们认为，正确了解远程桌面的隐私安全具有当前的重要意义。

尽管有大量关于加密流量侧信道信息泄露[6]–[16]和加密流量分类[17]的相关工作，但远程桌面场景中很少有探讨，除了[18]。[18]侧重于大致区分语音会议、视频会议、文本聊天、文件传输和TeamViewer加密流量的正常远程会议。然而，这五种行为位于典型远程控制软件的范围之外，注意力并不在侧信道信息泄露上。我们与[18]不同之处在于，我们对远程控制时执行更加敏感的日常活动（如阅读文档或使用Ofﬁce Word进行编辑）进行了调查。我们的调查包括在六种最流行的远程桌面软件上预定义五种日常活动，并仅收集数据包长度或到达时间信息，并使用可用的机器学习分类器确定对手是否可以从侧信道信息泄露的角度区分不同活动所附加的流量。此外，我们还进行了更深入的研究，以查看对手甚至是否可以检测用户在编辑时使用的特定工具种类。我们在本文中的贡献可以简要概述如下： • 我们系统地检查用户使用远程桌面软件远程控制设备时，细粒度侧信道信息泄露问题。结果显示，我们所分析的六种最受欢迎和最先进的远程桌面软件都存在泄漏用户粗略甚至细粒度活动隐私信息的风险。远程桌面的用户和提供者都必须更加关注这种严重的隐私泄露问题。

## 

---

 ## 原文[1/6]： 

 
 • We show that machine learning techniques based on decision tree are extremely good enough to determine the activity label with low false positive rate and high true positive rate, especially combined with ensemble techniques, which stresses the severity of privacy leakageof remote desktop again.

 The remainder of the paper is organized as follows. Sec tion II outlines the related work. In Section III we present our methodology. Our dataset creation is detailed in Section IV, followed by a comprehensive experimental evaluation in Sec tion V. Finally, we conclude in Section VI. Side-channel information leakage problem of encrypted trafﬁc has aroused the academia and industry’s attention for lots of years, and there are many valuable related works in various circumstances. D.Song et al. [7] successfully con ducted a keystroke attack on SSH, their result also applied to general encrypting interactive protocols. D.Brumley and D.Boneh devised a timing attack against OpenSSL to extract private keys, which demonstrates that timing attacks against network servers are practical [6]. The authors of [8] found that detailed sensitive information was being leaked out from web applications despite HTTPS protection. [13] showed it was possible for an adversary to know the https adaptive video stream title. In [9], [10], [15] authors gone into the personal living activities or device ﬁngerprint information leakage of radio signal such as wireless transmissions, keystroke’s acous tic signal. C. V. Wright et al. inspected that an adversary can uncover spoken language and even spoken phrases with HMM technique of encrypted VoIP [11], [12]. H. Li et al. observed that attackers can readily infer a user’s basic activities of daily living based on encrypted video stream [16]. On the other hand, recently many works have put forward machine learning based novel methods on encrypted trafﬁc classiﬁcation to achieve state-of-the-art performance [17] and the statistic feature of ﬂow burst has drawn much attention. T. S¨ober et al. [15] trained a model with 23 burst statistic characteristics to classify encrypted trafﬁc of 15 kind ap plications, they used knn and svm as their classiﬁers. After taking more than 23 bursts as a whole, they ﬁnally achieved a median classiﬁcation error rate of 0 %. R.Dubin of [13] encoded the total number of bits in every peak of the stream into a feature to ensure the title of encrypted http video stream, they used variations of k-nearest neighbors algorithm (k-NN) [19] and support vector machine (SVM) [20] as their classiﬁers. A. Naami used length, time, and count features of bi-directional burst combined with weighted knn, bind knn and bind random forest algorithms to classify different website and apps encrypted trafﬁc [21]. Inspired by the efﬁciency of ﬂow burst, we also extract similar statistic features of burst as input vector to our machine learning classiﬁers. There are also some research about classifying encrypted trafﬁc with deep learning for the powerful representative ability of deep learning, asdescribed in the reviewer [22].

 All previously mentioned works not only side-channel but also encrypted trafﬁc classiﬁcation seldom focus on the scenario of remote desktop except [18]. R. Altschaffel in [18] proposed an approach to extract statistic features aiming at distinguishing between ﬁle transfers, voice conferences, video conferences, text chat and normal sessions trafﬁc within Teamviewer and achieved good results from the point of encrypted trafﬁc classiﬁcation. However, the main weakness of [18] is that the ﬁve actions investigated are too rough and the ﬁrst 4 actions are actually not very relevant to control a remote computer with mouse or keyboard, and the focus is just on only one remote desktop: Teamviewer. Thus, experiments of [18] are not good enough to reveal the side-channel information leakage problem in the remote desktop scenario. In this section, we introduce the details of the targets we analyzed, the adversary model, performance metrics, and theclassiﬁers we chose.

 A. Remote Desktops Under Analysis There are two main open remote desktop protocols. One of them is Frame Buffer Protocol(RFB) [23] which is used by VNC series tools and the other one is Remote Desktop Pro tocol (RDP) [24] used by Microsoft remote desktop service. Most of the other remote desktop softwares, i.e., TeamViewer, tend to utilize their own proprietary remote desktop protocol. We describe six most popular products of remote desktop which play as a basis for our study as follows. We selected these products for two main reasons. Firstly, they are rep resentative because they cover the main properties of major remote desktop softwares. Secondly, they are also the leaders of remote desktop softwares for their market presence andcustomer satisfaction [25].  

---

 ## 翻译[1/6]：
 

我们发现，基于决策树的机器学习技术非常适用于确定具有低误报率和高真实阳性率的活动标签，特别是与集成技术相结合，这强调了远程桌面隐私泄露的严重性。本文的其余部分如下，第二部分概述相关工作。在第三节中，我们介绍我们的方法论。我们的数据集创建在第四节中详细介绍，接下来，在第五节中进行了全面的实验评估。最后，在第六节中进行总结。加密流量的侧信道信息泄漏问题已引起学术界和行业的关注许多年，并且在各种情况下存在许多有价值的相关作品。Song等人（7）成功地对SSH进行了击键攻击，他们的结果也适用于一般加密交互协议。Brumley和Boneh设计了一个针对OpenSSL的时间攻击以提取私钥，这证明了网络服务器的时间攻击是实用的（6）。[8]的作者发现，尽管受到HTTPS保护，并且详细的敏感信息正在从Web应用程序中泄漏出来。[13]表明，攻击者可以了解https自适应视频流标题。在[9]，[10]，[15]中，作者深入研究了个人生活活动或设备指纹信息泄漏的无线电信号，例如无线传输，击键的声学信号。Wright等人检查了使用HMM技术的对加密VoIP进行口语和甚至口语短语推测（11）（12）。Li等人观察到攻击者可以根据加密视频流轻松推断出用户的基本日常活动（16）。另一方面，最近许多工作提出了基于机器学习的加密流量分类的新方法，以实现最先进的性能（17），流突发的统计特征引起了许多关注。S¨ober等人（15）训练了一个具有23个突发统计特征的模型，用于分类15种应用程序的加密流量，他们使用knn和svm作为其分类器。将超过23个突发作为整体后，他们最终实现了0％的中位分类错误率。Dubin of [13]在流中对每个峰值的总位数进行编码，以确保加密http视频流的标题，他们使用k-NN的变化（k-NN）[19]和支持向量机（SVM）[20]作为其分类器。Naami使用双向突发的长度，时间和计数特征，结合加权knn，绑定knn和绑定随机森林算法来分类不同的网站和应用程序加密流量（21）。受到流突发的效率启发，我们还从波动的角度提取了类似的统计特征作为输入向量到我们的机器学习分类器。也有一些关于使用深度学习对加密流量进行分类的研究，因为深度学习代表能力强，如评论者所述[22]。先前提到的所有作品，不仅侧面信道，而且加密流量分类很少关注远程桌面场景，除了[18]。Altschaffel在[18]中提出了一种方法，以提取统计特征为目标，旨在区分Teamviewer中的文件传输，语音会议，视频会议，文本聊天和正常会话流量，并从加密流量分类的角度获得了良好的结果。然而，[18]的主要弱点是研究的五种动作过于粗略，前四种动作实际上与使用鼠标或键盘控制远程计算机并不相关，而重点仅在一个远程桌面上：Teamviewer。因此，[18]的实验不足以揭示远程桌面情景中的侧面信道信息泄漏问题。在本节中，我们介绍了我们分析的目标，攻击者模型，性能指标和我们选择的分类器的详细信息。

A.分析的远程桌面有两个主要开放远程桌面协议。其中之一是帧缓冲器协议（RFB）[23]，它由VNC系列工具使用，另一个是Microsoft远程桌面服务使用的远程桌面协议（RDP）[24]。大多数其他远程桌面软件，即TeamViewer，倾向于利用自己专有的远程桌面协议。我们描述了我们的研究基础的六个最受欢迎的远程桌面产品，如下所示。我们选择这些产品有两个主要原因。首先，它们是具有代表性的，因为它们涵盖主要远程桌面软件的主要属性。其次，由于它们在市场上的存在和用户满意度，它们也是远程桌面软件的负责人。[25]。

## 

---

 ## 原文[2/6]： 

 
 1) RealVNC [4] is based on RFB protocol. The single graphics primitive of RFB is to draw a rectangle of pixel data at a given position, which is somehow like the way encoding video. There are various encodings of the pixel data such as TRLE or ZRLE that can be dynamically selected according to network bandwidth, client drawing speed [23]. RealVNC uses 256-bit AES algorithm to encrypt the remote desktop sessions. 2) Microsoft Remote Desktop Service (MicroRDS) [26] uses RDP protocol. A RDP server only encodes the nec essary rendering information to the client to reconstruct corresponding display output [24], which differs from RFB. RDP uses RC4 cipher for secure communicationsover networks.

 3) Teamviewer [3], Anydesk [27], ConnectWise [28] and Zoho Assist [29] stand for proprietary remote desktop protocols based tools. They have not yet disclosed the details of their implementation, and we can only learn their manners of encryption from their self-evaluation reports. TeamViewer trafﬁc is secured using RSA pub lic/private key exchange and AES 256-bit session en cryption. AnyDesk encrypts all its connections using TLS1.2 cryptographic protocol. ConnectWise Control and Zoho Assist provide encrypted communications withSSL and AES-256 encryption.

 B. Adversary Model In this paper, we assume an adversary who can passive collect the pure encrypted trafﬁc between a remote desktop server and client. It is valid for an adversary to make his collected network trafﬁc pure. For example, he can ﬁlter all the trafﬁc by ip address of TeamViewer Company or by the SNI ﬁeld of TLS handshakes [30], he can also learn a machine learning based classiﬁer to identify remote desktop network trafﬁc. The adversary only has the ability to extract packet length and packet arrived time side-channel information, and he cannot get the plain message from the encrypted data frame. However, he might gain labeled training dataset from his own lab and train a strong generalized model to classify rough orﬁne activity trafﬁc.

 C. Selected Classiﬁers We assess four available machine learning classiﬁers be low to see their efﬁciency in classifying encrypted remote desktop trafﬁc: 1) logistic regression (LR) [31]. 2) support vector machine (SVM) [20]. 3) gradient boosting decision tree (GBDT) [32]. 4) random forest (RF) [33]. These classiﬁers are commonly used in the encrypted trafﬁc classiﬁcationcommunity.

 D. Metrics We evaluate all the classiﬁers mentioned in III-C based on the True Positive Rate (TPR), False Positive Rate (FPR) and F1-score. TPR measures how many fractions of real positive samples are correctly classiﬁed as positive, while FPR is calculated as the error ratio as wrongly categorizing negative samples as positive. We also use Precision Rate which is the fraction of relevant instances among retried instances in our run charts. F1-score is a measure of accuracy which considers both the precision and the recall of classiﬁer to computer a real between 0 and 1, where F1-score reaches its best valueat 1.  

---

 ## 翻译[2/6]：
 

1) RealVNC [4]基于RFB协议。RFB的唯一图形原语是在给定位置绘制一个像素数据矩形，这与视频编码的方式有些相似。像素数据有多种编码方式，例如TRLE或ZRLE，可以根据网络带宽、客户端绘图速度等动态选择[23]。RealVNC使用256位AES算法加密远程桌面会话。2) Microsoft Remote Desktop Service(MicroRDS)[26]使用RDP协议。 RDP服务器只对客户端进行必要的渲染信息编码以重构相应的显示输出[24]，这与RFB不同。RDP使用RC4密码进行网络上的安全通信。

3) Teamviewer [3]，Anydesk [27]，ConnectWise [28]和Zoho Assist [29]代表基于专有远程桌面协议的工具。它们尚未披露其实现细节，我们只能从其自我评估报告中了解其加密方式。TeamViewer使用RSA公共/私有密钥交换和AES 256位会话加密来保护流量。AnyDesk使用TLS1.2加密协议加密所有连接。ConnectWise Control和Zoho Assist使用SSL和AES-256加密提供加密通信。

B. 对手模型：在本文中，我们假设对手能够被动地收集远程桌面服务器和客户端之间的纯加密流量。对于一个对手来说，使他收集的网络流量变为纯的是有效的。例如，他可以通过TeamViewer公司的IP地址或TLS握手中的SNI字段[30]过滤所有流量，他还可以学习基于机器学习的分类器来识别远程桌面网络流量。对手只能提取数据包长度和到达时间侧信道信息，无法从加密数据帧中获取明文消息。但是，他可能会从自己的实验室中获取标记的训练数据集，并训练一个强大的分类器模型来对某些粗略或细微的活动流量进行分类。

C. 选择的分类器：我们选取了四种可用的机器学习分类器来评估它们在分类加密的远程桌面流量方面的效率：1) logistic regression(LR)[31]；2)support vector machine(SVM)[20]；3) gradient boosting decision tree(GBDT)[32]；4) random forest(RF)[33]。这些分类器在加密流量分类社区中广泛应用。

D. 度量指标：我们基于真正例率（TPR），误报率（FPR）和F1-score评估III-C中提到的所有分类器。TPR度量正确分类的正样本的比例，FPR则计算错误分类的负样本的比例。我们还使用Precision Rate，在我们的运行图中表示提取的实例中相关实例的比例。F1-score是一种精度度量，考虑了分类器的精度和召回率，计算出0到1之间的真实值，其中F1-score在1时达到最佳值。

## 

---

 ## 原文[3/6]： 

 
 In this part, we demonstrate our 3 processes of creating dataset: trafﬁc generation, feature extraction, dataset split andnormalization.

 A. Trafﬁc Generation To investigate the ﬁne side-channel information leakage problem of remote desktop softwares, we needed to generate remote desktop trafﬁc ﬁrstly. We used a cloud host with Windows Server 2016 64bits as a remote desktop server, and two kinds of customer hosts of Windows 10 64bits and Windows 7 64bits to simulate the real circumstance where a user connects to a remote cloud server. We deﬁned 5 rough activities: editing-documents, reading-documents, watching videos, surﬁng-webs, and installing-softwares. The details of these activities can be found in Table I. The activities and tools mentioned were common in our daily ofﬁce. To gen erate different person’s patterns of these activities, we ﬁrstly asked 10 persons to perform each activity above for about 20 minutes, and recorded their time intervals of consecutive keyboard hit and mouse click or movement events as action templates. Secondly, we replied these time intervals of action templates from a random start point with random keys of keyboard or mouse for each action onto MicroRDS, RealVNC, Teamviewer, and Anydesk, and captured the encrypted trafﬁc for 30 seconds as a trafﬁc sample with corresponding labels. It was more dangerous to leak user’s information of editing tool, so we performed editing-documents actions on two addi tional softwares, ConnectWise and Zoho Assist, and we added an additional label of editing-software to the trafﬁc besides editing-documents label, for just making our results more representative. We regarded these actions with an additional label as ﬁne activities of editing-documents. We puriﬁed the network trafﬁc by some process-level network sniffer such Commviewer [36], which maps packets to application. Table II shows the statistic of our pure raw captured trafﬁc. B. Feature Extraction Since our adversary cannot decrypt the trafﬁc to gain plain message, he must make use of the side-channel information: packet length and packet arrived time. In this stage, we introduce our 66 statistic features of burst based on the side channel information of each ﬂow. A sequence of consecutive packets forms a burst if there is an idle time interval greater than a threshold t before and after them [15]. A too small t might wrongly split a sequence of correlated packets into pieces of small bursts, while a too large threshold tends to push unrelated packets together. [35] and [15] suggested a threshold of 4.5 seconds is suitable for smartphones’ ﬁngerprints. How ever, we observed this value was not proper in the scenario of real-time interaction of remote desktop for the reason that the action of keystroke or mouse click did not persist so long, and we tested three thresholds of 0.2s, 0.5s, 0.8s, and 1s to ﬁnd the best threshold adaptively. We used moments of different order and percentiles of packet sizes and arrived time intervals of a burst as our main features. The details of the features used inthis paper can be found in Table III.

 C. Dataset split and normalization After we extracted the 66 features mentioned in IV-B and built up a dataset, we need to split the dataset into 3 subsets: training set, validation set and test set. On the one hand, they shared nothing with each other. On the other hand, their union formed the whole dataset. We split 10 % of them into test set, and 90% of the rest vectors were used for training models and 10% were used for validation. We also applied 10-fold cross-validation before evaluating the model on the test set. To eliminate the effect of the fundamental unit of different features, we normalized our dataset before classiﬁcation. We utilized standard score normalization where each feature was calculated by dividing the difference between the feature andthe mean by the standard deviation.  

---

 ## 翻译[3/6]：
 

在本部分，我们展示了创造数据集的三个过程：流量生成、特征提取、数据集划分和归一化。

A. 流量生成为了研究远程桌面软件的精细侧信道信息泄露问题，我们首先需要生成远程桌面流量。我们使用了一个64位的Windows Server 2016云主机作为远程桌面服务器，以及两种不同的客户主机，即64位的Windows 10和Windows 7，来模拟一个用户连接到远程云服务器的真实场景。我们定义了5个粗略的活动：编辑文档、阅读文档、观看视频、上网冲浪和安装软件。这些活动和工具在我们日常办公中很常见。为了生成不同的人的这些活动模式，我们首先请10个人分别执行每个活动约20分钟，并记录他们连续击键和鼠标单击或移动事件的时间间隔作为动作模板。其次，我们对此随机选择开始点和随机键盘或鼠标按键，对MicroRDS、RealVNC、Teamviewer和Anydesk的每个动作进行重复，并捕获30秒的加密流量作为带有相应标签的流量样本。由于泄漏用户编辑工具的信息更加危险，因此我们在ConnectWise和Zoho Assist上执行了编辑文档操作，并在编辑文档标签之外添加了一个编辑软件标签，以使结果更具代表性。我们使用了一些处理级网络嗅探器（如Commviewer [36]）来净化网络流量。表II显示了我们的纯原始捕获流量的统计信息。

B. 特征提取由于我们的对手不能解密流量以获取明文消息，因此他必须利用侧信道信息：数据包长度和到达时间。在这个阶段，我们介绍了基于每个流的侧通道信息的66个连续数据包的突发统计特征。如果存在一个空闲时间间隔大于阈值t在它们之前和之后，一系列连续的数据包形成了一个突发[15]。一个太小的t可能会错误地将一系列相关的数据包分成小突发，而一个太大的阈值则倾向于将不相关的数据包推在一起。[35]和[15]建议4.5秒的阈值适合智能手机的指纹，然而，我们观察到这个值在远程桌面的实时交互场景中不适用，因为按键或鼠标点击的动作不会持续那么长时间，我们测试了0.2秒、0.5秒、0.8秒和1秒的三个阈值，以自适应地找到最佳阈值。我们使用不同阶数的矩和突发的包大小和到达时间间隔的分位数作为我们的主要特征。在本文中使用的功能的详细信息可以在表III中找到。

C. 数据集划分和归一化在提取了IV-B中提到的66个特征并构建了数据集之后，我们需要将数据集划分为3个子集：训练集、验证集和测试集。一方面，它们之间没有任何共享。另一方面，它们的并集形成了整个数据集。我们将其中的10％划分为测试集，其余90％的向量用于训练模型，10％的向量用于验证。在评估测试集之前，我们还执行了10倍交叉验证。为了消除不同特征的基本单位的影响，我们在分类之前对我们的数据集进行了归一化。我们使用标准分数归一化，其中每个特征通过将特征减去平均值并除以标准差来计算。

## 

---

 ## 原文[4/6]： 

 
 V. EXPERIMENT EVALUATION This section reports our experimental evaluation. Firstly, we evaluated the performance of LR, SVM, GBDT and RF algorithms on the single burst to show their capabilities on classifying encrypted trafﬁc of remote desktop. We found the performance on just single burst was inadequate, then we regarded several adjacent bursts as a whole and performedsupplementary experiments on them.

 A. Single burst classiﬁcation We ﬁrstly inspected the capability of our approach with just a single burst for each classiﬁcation. We evaluated rough activities and ﬁne activities classiﬁcation on each remote desktop independently. The seasons of this setting was that each remote desktop had its implementation on how to handle the network trafﬁc and it was not suitable to consider all of them together. Firstly, we evaluated the best time intervalthreshold t to cut bursts.

 The result in Fig 2 shows that the larger threshold tends to gain a better performance when the threshold is less or equal than 0.8s. We held the view that a larger threshold tended to gather more packets into a single burst, where machine learning algorithm could aggregate more useful information from it. However, when the threshold is set too large, e.g. 1s, we observe a reduction of average precision for a too large threshold forced unrelated packets into an entity which disrupts the classiﬁers. So we chose 0.8s as our time interval threshold. What we must emphasize is that the threshold value 0.8s may be just a local optimal threshold, someone can enumerate the other possible thresholds to get better results. However, the main focus of this work is to reveal the side channel leakage problem of remote desktop scenario. A local optimal threshold is sufﬁcient to achieve our goal if such local optimal threshold leads to excellent classiﬁcation performance. Table IV and Table V show the results of single burst for each remote desktop software and for each machine learning algorithm used. The results depict that: 1). None of the six remote desktops protects user’s activity privacy well from side-channel leakage. An adversary can infer the activity of a user with at least 80.19% TPR for rough actions and 75.94% TPR for ﬁne actions with the help of GBDT algorithm. 2). It’s possible for an adversary to detect user’s edit tool because different edit-tools have different manners of work. For example, the edit cursor in notepad++ blinks with a faster frequency than that in notepad, and notepad++ also lists some candidates whose function is not supported by notepad. 2). Among the six remote desktops, RealVNC is the worst one on protecting users’ rough activities. The way of encoding pixel data of screen somehow like videos might play an important role in leaking user’s privacy. 3). Different machine learning algorithms have their capabilities on activities classiﬁcation. Logistic regression has the lowest performance because of its simplicity, while algorithms of GBDT and RF come to the best, and GBDT acts a little better than RF. SVM is also suitable for this task which acts better than LR, but we ﬁnd it is the most time-consuming in our experiments. GBDT and RF algorithms are both ensemble learning methods, they obtain better predictive performance than LR and SVM by combiningseveral weak classiﬁers .  

---

 ## 翻译[4/6]：
 

五、实验评估 本节报告了我们的实验评估结果。首先，我们评估了LR、SVM、GBDT和RF算法在单个爆发中的性能，以展示它们对于分类远程桌面加密数据的能力。我们发现仅在单个爆发中的性能是不足的，因此我们将几个相邻的爆发整合为一个，对它们进行了补充实验。

A. 单个爆发分类 我们首先检查了我们的方法在每个分类中只使用单个爆发的能力。我们独立评估了每个远程桌面的粗略活动和精细活动分类。这种设置的原因是每个远程桌面都有自己的实现方式来处理网络数据流量，考虑将它们全部纳入到一起是不合适的。首先，我们评估了最佳时间间隔阈值t来割断爆发。

图2的结果显示，当阈值小于或等于0.8秒时，较大的阈值 tends to gain a better performance。我们认为，较大的阈值倾向于将更多数据包聚合成一个爆发，机器学习算法可以从中聚合更多有用的信息。但是，当阈值设置得过大时，例如为1秒，我们观察到平均精度降低，因为阈值过大会将无关的数据包强制聚合成为一个实体，这会影响分类器的性能。因此，我们选择0.8秒作为我们的时间间隔阈值。需要强调的是，阈值值0.8秒可能只是一个局部最优阈值，有些人可以枚举其他可能的阈值以获得更好的结果。但是，本研究的主要重点是揭示远程桌面场景中的侧信道泄漏问题。如果这样的局部最优阈值可以达到出色的分类性能，则足以实现我们的目标。表IV和表V显示了每个远程桌面软件和每个使用的机器学习算法的单个爆发结果。结果表明：1）六个远程桌面都不能保护用户的活动隐私免受侧信道泄漏。攻击者可以通过GBDT算法以至少80.19％的TPR获得用户的粗略行动和75.94％的TPR获得用户的精细行动的活动。2）攻击者可以检测到用户的编辑工具，因为不同的编辑工具有不同的工作方式。例如，notepad++中的编辑光标闪烁频率比notepad更快，在notepad++中还列出了一些通用功能，而这些功能在notepad中不受支持。2）在六个远程桌面中，RealVNC是保护用户粗略活动最差的一个。屏幕像素数据编码方式有些类似于视频，可能在泄漏用户隐私方面起着重要作用。3）不同的机器学习算法具有各自的活动分类能力。由于其简单性，逻辑回归的表现最差，而GBDT和RF算法则表现最佳，GBDT略好于RF。SVM也适用于此任务，比LR表现更好，但我们发现它在我们的实验中耗时最长。GBDT和RF算法都是集成学习方法，通过组合多个弱分类器获得更好的预测性能，比LR和SVM获得更好的性能。

## 

---

 ## 原文[5/6]： 

 
 B. Consecutive bursts classiﬁcation Although an adversary can gain a not bad true positive rate (76.55 % average TPR for rough action, 72.15% average TPR for ﬁne action among the four classiﬁers) when he detects the actions of a user based on a single burst, he can also regard several consecutive bursts as a whole to ensemble his models because consecutive bursts mean related units of an action. In this section, we used two different methods to combine several bursts. We deﬁned a sliding window k, whose range is {1, 3, 6, 8, 12}, and we considered k consecutive bursts as an entity. For the ﬁrst way, we summed up each vector of an entity to gain a representative vector for it, which was then fed into the four classiﬁers. As for the second way, we classiﬁed k bursts of an entity and took the majority vote of the k labels, which was the same manner as [15]. We then applied these two methods on different algorithms and different remote desktop. Fig 3 details the improvement of precision when we combined k bursts on GBDT algorithm. From Fig 3, we observe that both the way of addition and vote improve the precision dramatically, and the way of vote performs greatly better than the way of addition. With setting k as 12 and combination method as vote, we ﬁnally reached our best average precision of 96.45% for rough actions and 99.24% for ﬁne actions, where the average TPR, FPR and F1-score for rough actions of remote desktop softwares is 99.26%, 0.57%, 97.17% while 99.11%, 0.28%, 99.15% for ﬁne actions. This result reveals that the encryption mechanism is nothing sufﬁcient to prevent side-channel information leakage for remote desktop. In this paper, we access the side-channel information leak age problem of remote desktop. The results of our experiments show that the activity such as reading-documents or editing with ofﬁce Word 2007 of a user when he uses a remote desktop software can be identiﬁed with a high true positive rate for the trafﬁc encryption between the client and the server. This work is the ﬁrst one to evaluate such a ﬁne-grained side channel information leakage problem of remote desktop. We used four different supervised machine learning models for this task and collected a large dataset of trafﬁc bursts from the real world. After training these models on the collected dataset adequately and combining several consecutive bursts together we gained a high TPR at 99.26% for rough actions and 99.15% for ﬁne actions. Our experimental results demonstrate that the encryption mechanism could not protect user’s activity privacy in the scenario of remote desktop, which should be concerned by remote desktop providers and users who perform sensitive activities with remote desktop in the future. This work is supported by The National Key R&D Program of China (No. 2016YFB0801200 and No. 2016QY05X1000) and The National Natural Science Foundation of China (No. U1636217 and No. 61702501) and The Key research and Development Program for Guangdong Province under grant No. 2019B010137003. Junzheng Shi is the correspondingauthor.

  

---

 ## 翻译[5/6]：
 

B. 连续突发分类

尽管对于基于单个突发来检测用户动作的入侵者，他可以获得不错的真正阳性率(粗略动作的平均TPR为76.55%，细微动作的平均TPR为72.15%，其中有四个分类器)，但他也可以将连续的若干个突发视为一个整体来组合他的模型，因为连续的突发意味着一个动作的相关单位。在本节中，我们使用了两种不同的方法来组合几个突发。我们定义了一个滑动窗口k，其范围是 {1，3，6，8，12}，并认为k个连续的突发是一个实体。对于第一种方法，我们将实体的每个向量相加，得到一个代表性向量，然后将其输入四个分类器。至于第二种方法，我们对一个实体的k个突发进行分类，并采取k个标签的多数投票，这与[15]的方式相同。然后，我们在不同的算法和不同的远程桌面上应用这两种方法。图3详细说明了在GBDT算法上组合k个突发时精度的改进情况。从图3可以看出，加法和投票都显著提高了精度，而投票的方式比加法的方式要好得多。设置k为12和组合方法为投票，我们最终得到了粗略动作的最佳平均精度为96.45%，细微动作的最佳平均精度为99.24%，其中远程桌面软件的粗略动作的平均TPR、FPR和F1得分分别为99.26%、0.57%、97.17%，而细微动作的平均TPR、FPR和F1得分分别为99.11%、0.28%、99.15%。这个结果表明，加密机制并不足以防止远程桌面侧信道信息泄露。本文探讨了远程桌面的侧信道信息泄漏问题。我们的实验结果表明，当用户使用远程桌面软件时，像阅读文档或编辑Office Word 2007之类的活动可以通过客户端和服务器之间的流量加密以高真正阳性率得到识别。这项工作是第一个评估远程桌面细粒度侧信道信息泄漏问题的工作。我们为此任务使用了四个不同的监督机器学习模型，并从现实世界收集了大量的流量突发。在足够训练这些模型的收集数据集和组合多个连续爆发之后，我们获得了粗略动作的高TPR(99.26%)和细微动作的高TPR(99.15%)。我们的实验结果表明，加密机制不能保护用户在远程桌面场景中的活动隐私，这应该引起远程桌面提供商和使用远程桌面进行敏感活动的用户的关注。本工作得到了中国国家重点研发计划(No.2016YFB0801200和No.2016QY05X1000)、中国国家自然科学基金(No.U1636217和No.61702501)和广东省重点研发计划(编号2019B010137003)的支持。Junzheng Shi是本文的通讯作者。

