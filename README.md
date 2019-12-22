마크다운 문법 (Markdown)
=====================

무언가를 기록하고 그것을 잘 정돈하여 본다는 것은 얼마나 중요한지 모르겠습니다. 예전에는 정성스럽게 정리된 다이어리나 노트들이 그러한 고민과 노력을 대변하곤 하였습니다. 하지만 현대에 들어서 모든 자료들이 디지털화되고 웹상에서 공유되기 시작하면서 이제 모든 것을 컴퓨터에 기록하는 시대가 되었습니다.

하지만 안타깝게도 이러한 기록문서의 형식에는 너무 다양한 종류가 있습니다. 메모장과 워드의 파일 형식이 다르고 웹에서 사용되는 문서와도 다릅니다. 각각의 문서편집기마다 다른 형식이 사용되는 바람에 이들은 서로 호환이 잘 되지 않습니다. 그렇다면 지금은 물론 먼 미래까지 생각한다면 과연 어떤 문서형식으로 기록하고 정리하는 것이 최선의 방법일까요? 여기 한가지 멋진 해결책을 소개해 봅니다.


## 마크다운 문법 소개

### 블로그 글쓰기의 어려움

글이라는 것은 단순히 문자로 이루어진 것인데 왜 이렇게 많은 문서형식이 필요할까요? 그 이유는 바로 '서식'에 있습니다. 워드에서 사용되는 문자나 메모장에서 사용되는 문자나 문자형식은 같습니다. 하지만 메모장에서는 '디자인'요소가 거의 없다시피 합니다. 반면에 워드에서는 글자의 크기와 색깔, 문장의 구조, 표와 그림까지 문서에 삽입할 수 있습니다. 이렇게 문자외에도 문자가 표시되는 방식과 부가내용들을 표현하기 위해 각 프로그램들마다 저마다의 표현방법을 개발했기에 여러 문서형식이 만들어지게 되었습니다.

웹에서는 어떨까요? 위와 같은 관점에서 본다면 웹은 매우 독특한 공간입니다. 왜냐하면 오직 웹만이 운영체제나 문서편집기에 상관없이 약속된 표준이 존재하기 때문입니다. 어찌보면 당연한 일입니다. '공유'가 안되는 웹은 의미가 없기 때문입니다. 만약 약속된 표준이 없다면 웹에서 어떻게 문서를 읽을지 상상해 보십시오. 워드로 작성된 문서를 보려면 워드 뷰어를 깔고, 다른 편집기로 작성된 문서를 열려면 또다른 뷰어를 설치해야 할 것입니다. 두말할 나위없이 이러한 방식은 비효율적이기 때문에 웹문서 형식인 html만큼은 W3C라는 협회에서 제정한 문서형식의 표준이 존재합니다. 이 표준은 시대의 흐름에 따라 발전해서 현재는5번째 버전(HTML5)까지 나왔지만 하위 호환성을 중요시하기 때문에 그 이전 버전의 문서도 최신 브라우저에서 얼마든지 읽을 수 있습니다. 아, 그렇다면 html은 우리가 찾던 문서형식의 강력한 후보가 되는 셈입니다.

브라우저에서 보여지는 모든 것은 이 html 문서입니다. 지금 읽고 있는 이 블로그도 마찬가지이지요. 그런데 블로그는 html로 이루어져 있는데 역설적이게도 블로그 글을 html로 작성하는 사람은 없다고해도 과언이 아닙니다. 무슨말이냐 하면 전문 html 편집기가 아니라 메모장에서 html 문서 표준을 따라 글을 쓰는 사람들이 없다는 것입니다. 왜 그럴까요? 이유는 간단합니다. 글쓰기가 무척 어렵기 때문입니다. 다음은 html 양식으로 쓰여진 글입니다.

```html
<h1> 마크다운 메모와 위키와 책 </h1>
<p> 마크다운은 다음과 같은 장점이 있습니다.</p>
<ul>
	<li> 문법이 단순하여 배우기 쉽고 쓰기도 쉽습니다. </li>
    <li> html 문서로 변환되지 않아도 그 자체로 충분히 읽을 수 있습니다. </li>
    <li> 다양한 도구들을 이용해 손쉽게 html 문서로 변환될 수 있습니다 </li>
</ul>
```

위의 글은 html 형식을 맞춰서 쓴 글입니다. **태그**라고 불리는 꺽쇠 문자가 모든 문장 앞뒤로 적어진 것을 알 수 있습니다. h1, p, ul과 같은 각 꺽쇠 안의 문자들은 문장의 '서식'을 나타냅니다. 다시말해 html문서를 메모장으로 작성하려면 모든 문장에 태그를 달아주어야 하며 특별한 서식에는 훨씬 많은 태그가 필요합니다. ~~특히 테이블을 표현하는 태그가 복잡하기로 악명이 높습니다.~~ 반면에 아래 글은 어떤가요?

```txt
마크다운 메모와 위키와 책
===========================

마크다운은 다음과 같은 장점이 있습니다.

 * 문법이 단순하여 배우기 쉽고 쓰기도 쉽습니다.
 * html 문서로 변환되지 않아도 그 자체로 충분히 읽을 수 있습니다.
 * 다양한 도구들을 이용해 손쉽게 html 문서로 변환될 수 있습니다
```

위의 글은 html과 마찬가지로 메모장에서 작성되었지만 기호를 통해서 서식을 일부 표현하고 있습니다. 때문에 html로 작성된 문서보다 훨씬 직관적이고 각 기호가 어떠한 용도로 쓰였는지도 쉽게 알 수 있습니다. 마크다운 문법은 바로 이와같이 흔히 사용되는 관용적인 기호서식들을 발전시켜 단순한 txt 문서를 html 문서로 쉽게 변환할 수 있도록 만든 문법을 말합니다.



### 마크다운 문법이란?

마크다운 문법은 존 그루버(John Gruber)와 아론 스워츠(Aaron Swartz)가 메일의 글쓰기 형식에서 영감을 받아 만들었으며 자신의 블로그에 마크다운 문법 소개와 함께 python으로 만든 html 변환기(마크다운 문서->html)를 올림으로써 알려지게 되었습니다. 위에서 보는 것 같은 여러 장점들로 인해 문법은 빠르게 확산되었고 지원 툴들도 여럿 만들어 졌지만 안타깝게도 존 그루버가 약 10년전 문법을 제시한 이후 별다른 새 표준을 제시하지 않아서 마크다운 표준 자체는 정체되어 있는 상태입니다. 현재는 각 커뮤니티 등에서 이를 조금씩 발전시켜서 새로운 문법을 만들고 있지만 때문에 권위있는 표준없이 새 표준이 난립하는 파편화가 진행되고 있는 문제 역시 안고 있습니다. 마크다운 문서는 대체로 .md나 .markdown과 같은 확장자를 사용하지만 근본이 txt인지라 메모장에서도 잘 열립니다.

마크다운 문법의 장단점은 다음과 같습니다.

* 장점
 - 문법이 단순해서 배우기 쉽고 쓰기도 쉽습니다.
 - html 문서로 변환하지 않아도 그 자체로 충분히 읽을 수 있습니다.
 - 다양한 도구들을 이용해 손쉽게 html 문서로 변환될 수 있습니다.
 - inline HTML을 지원하기 때문에 html의 풍부한 기능을 그대로 사용할 수 있습니다.
 - 단순한 텍스트이기 때문에 어떤 운영체제나 편집기에서도 작성할 수 있습니다.
 - 단순한 텍스트이기 때문에 용량이 매우 작고 검색속도가 빠릅니다.
 - html로 변환되기 때문에 문서 호환성이 좋습니다.
* 단점
 - 문법이 너무 간단하고 오래되어서 테이블 등 새로운 서식에 대한 요구사항을 반영하지 못하고 있습니다.
 - 새 표준이 나오지 않아 [PHP Markdown Extra](https://michelf.ca/projects/php-markdown/extra/), [Multimarkdown](http://fletcherpenney.net/multimarkdown/), [Github Flavored Markdown(GFM)](https://help.github.com/articles/github-flavored-markdown) 등으로 파편화가 진행되고 있습니다.
 - 그림파일을 삽입/관리하기가 어렵습니다.

마크다운 문법의 위와 같은 단점은 그렇게 치명적이지는 않습니다. 새로 제정되고 있는 확장 문법들이 아닌 기본 문법으로도 블로그 등의 글을 충분히 쓸 수 있고, 새 문법들도 세세한 부분은 달라도 중요한 부분은 서로 공유하면서 발전시켜 나가고 있기 때문입니다. 따라서 기본 문법을 충실히 따르면서 꼭 필요한 부분만 확장 문법을 사용하면 큰 문제가 없습니다.

반면에 그림파일을 다루는 것은 조금 골치아픈 문제입니다. md문서는 텍스트 문서이기 때문에 워드처럼 그림파일이 문서에 합쳐진 문서가 아닙니다. 따라서 html과 마찬가지로 이미지를 링크하여 문서에 표시하고 있습니다. 때문에 그림파일을 동영상이나 음악재생처럼 웹에 올리고 서비스 되고 있는 url을 적어주거나 따로 이미지 파일들을 폴더에 모아두고 링크를 거기에 맞추어 관리해야 합니다. 이 문제는 html에서도 동일하게 나타나는 것이기 때문에 md문서의 잘못은 아니지만 불편한 것은 사실입니다.

하지만 이러한 몇가지 불편을 무시할 수 있을 만큼 마크다운은 큰 장점을 가지고 있으며 Simple(txt), Smart(html 자동변환), Steady(html의 표준)한 3S의 조건을 잘 만족시키고 있기 때문에 **S Life**에 잘 어울리는 기록 문서형식이라고 할 수 있겠습니다.


## 마크다운 문법 Syntax

### 기본 마크다운 문법 (존 그루버)

먼저 문법을 잘 정리한 공식사이트 링크를 소개합니다.  
* 공식사이트 : [Markdown: Syntax – Daring Fireball](http://daringfireball.net/projects/markdown/syntax)(영문)
* 놀부님이 친절하게 번역해 주셨습니다 : [존 그루버 마크다운 페이지 번역](http://nolboo.github.io/blog/2013/09/07/john-gruber-markdown/)
* 역시 놀부님이 소개하신 마크다운 사용법 : [간단한 마크다운 문법](http://nolboo.github.io/blog/2014/04/15/how-to-use-markdown/#간단한_마크다운_문법)

문법의 핵심은 html의 h1,h2,h3... 들이 나타내는 문장구조 태그와 강조 태그(이텔릭/볼드)와 링크 태그(하이퍼/이미지)입니다. 리스트도 매우 유용합니다. 종종 html 문서에서는 문장구조 태그가 무시되는 경우가 있는데 기록문서에서 이는 매우매우 유용하니 꼭 사용하는 것이 좋습니다. 이렇게 문장에 구조를 부여하면 자동으로 목차를 만들 수 있을 뿐 아니라 css를 통해서 일괄적으로 서식을 적용할 수 있어서 이점이 매우 큽니다. 아래는 기본 문법을 표로 정리한 것입니다. 자동 문자변환이나 매우 유용한 참조링크 등 몇가지 빠진 것이 있으니 되도록 공식 문법을 한번 정독할 것을 권합니다.

| 분류             | 결과                  | 문법                           |
|-----------------|-----------------------|-------------------------------|
| h1 - 문서 제목   | <h1>h1 문서입니다.</h1> | h1 문서입니다.<br/>===========  |
| h2 - 목차 제목   | <h2>h2 문서입니다.</h2> | h2 문서입니다.<br/>-----------  |
| h1 - 문서 제목   | <h1>h1 문서입니다.</h1> | # h1 문서입니다.                |
| h2 - 목차 제목   | <h2>h2 문서입니다.</h2> | ## h2 문서입니다.               |
| h3 - 목차 소제목  | <h3>h3 문서입니다.</h3> | ### h3 문서입니다.             |
| h4 - h3 하위 단계 | <h4>h4 문서입니다.</h4> | #### h4 문서입니다.            |
| h5 - h4 하위 단계 | <h4>h5 문서입니다.</h4> | ##### h5 문서입니다.           |
| h6 - h5 하위 단계 | <h4>h6 문서입니다.</h4> | ###### h6 문서입니다.          |
| 수평줄           | <hr/>                  | \*\*\* or ---    (3개 이상)   |
| 강조 - 이텔릭체   | <em>이텔릭체</em>        | \*이텔릭체\* or \_이텔릭체\_    |
| 강조 - 볼드체    | <strong>볼드체</strong>  | \*\*볼드체\*\* or \_\_볼드체\_\_|
| 강조 - 이텔릭+볼드 | <em><strong>이텔릭 볼드체</strong></em>                               | \*\*\*이텔릭 볼드체\*\*\* or \_\_\_이텔릭 볼드체\_\_\_  |
| 인용문           | <blockquote>인용문은 이렇게<br/>블록으로 지정됩니다.</blockquote>         | 인용문 맨 앞에 '>' 삽입                                |
| 리스트 - 무순서   | <ul><li>순서없이</li><li>점으로 나열</li></ul>                          | \* 순서없이 <br/> \* 점으로 나열 ('*'대신 '-'도 같은 결과)|
| 리스트 - 순서     | <ol><li>순서대로</li><li>번호가 매겨짐</li></ol>                        | 1. 순서대로<br/>2. 번호가 매겨짐                        |
| 링크 - 하이퍼     | <a> 하이퍼 텍스트 링크</a>                                             | \[하이퍼 텍스트 링크\]\(http://hyper/)                 |
| 링크 - 이미지     | <img alt="마크다운 로고" src="http://bit.ly/1nmhGjE">                 | \!\[마크다운 로고](http://bit.ly/1nmhGjE)              |
| 코드블럭          | <pre><code>funtion add(a,b){<br/>  return c=a+b;<br/>}</code></pre> | 코드문장 앞에 4칸 이상 공백이나 탭 하나                   |
| 코드삽입          | `<h1>This is code</h1>`                                             | 문장을 '\`'로 감싼다                                   |


### Github Flavored Markdown(GFM)

깃허브에서는 사이트와 위키 등에서 마크다운을 다소 확장한 문법을 사용하고 있습니다. 가장 큰 차이점 중 하나는 기본 마크다운은 엔터를 여러번 입력해도 하나만 인식하고 문단을 나누는 반면 깃허브는 엔터를 친만큼 그대로 인식해서 간격을 벌려준다는 것입니다. 또 코드블럭에서 구문을 강조할 문법을 지정할 수 있는 팬시드 코드블럭이 추가되었습니다. 그리고 목차 자동 생성 기능도 제공합니다. 글 중간에 [[TOC]]와 같이 입력해주면 목차가 h2,h3 등의 구조에 따라 자동으로 만들어 집니다. 이처럼 매우 유용한 확장된 기능들을 정의하고 있기 때문에 저도 GFM 문법까지는 사용하고 있습니다.

* 공식 사이트 : [Writing on GitHub](https://help.github.com/articles/writing-on-github), [GitHub Flavored Markdown](https://help.github.com/articles/github-flavored-markdown), [Mastering Markdown](https://guides.github.com/features/mastering-markdown/index.html)
* 놀부님이 번역하신 옛버전 문법 소개글 : [깃허브 취향의 마크다운 번역](http://nolboo.github.io/blog/2014/03/25/github-flavored-markdown/)

| 분류    | 결과                               | 문법                                                          |
|--------|------------------------------------|--------------------------------------------------------------|
| 취소선  | <del>취소선</del>                   | \~\~취소선\~\~                                                 |
| 코드블럭 | ```function add(a,b){}```         | \`\`\`java(강조할 문법이름) <br/> function add(a,b){}<br/>\`\`\` |
| 체크박스 | <input type="checkbox"/> checkBox | \- \[ \] checkBox                                             |


### PHP Markdown Extra

PHP Markdown Extra는 깃허브 다음으로 많이 사용되는 확장 문법입니다. 이 문법 역시 팬시드 코드블럭을 사용할 수 있습니다. 가장 눈에 띄는 것은 테이블 문법이 있다는 것입니다. 우리가 메모장에서 기호를 이용해 테이블을 만드는 방법을 그대로 사용하면서 정렬방식까지도 선택할 수 있습니다. (깃허브에서도 지원하게 되었군요) 또다른 주목할만한 기능은 각주를 달 수 있는 기능입니다. 다른 각종 위키들에서도 이러한 문법을 찾아볼 수 있습니다.

* 공식 사이트 : [PHP Markdown Extra](https://michelf.ca/projects/php-markdown/extra/)
* 놀부님이 번역하신 글 : [PHP 마크다운 확장 번역](http://nolboo.github.io/blog/2014/03/25/php-markdown-extra/)


테이블 작성요령은 다음과 같습니다.

```
| column | column | column | 
|:-------|-------:|:------:|
|   a    |   b    |   c    |
```

결과는 다음과 같습니다.

| column | column | column | 
|:-------|-------:|:------:|
|   a    |   b    |   c    |

눈치채셨을지 모르지만 테이블 두번째 줄에 ':'이 어디에 있느냐에 따라서 정렬방식이 바뀌는 것을 알 수 있습니다. c는 양쪽정렬입니다.


각주는 다음과 같이 사용합니다.
```
각주를 적용할 문장[^1]
.
.
[^1]: 이렇게 각주를 답니다.
```


### 그외

* 워드프레스에서도 지원하기 시작했습니다 : 칼킨님의 [워드프레스 마크다운(Markdown) 문법 설명](http://blog.kalkin7.com/2014/02/05/wordpress-markdown-quick-reference-for-koreans/)

<br/>
*※ 이 블로그도 마크다운 문서로 작성되었습니다. .md와 .html로 작성된 두 문서를 첨부했으니 비교해 보시기 바랍니다.*
<br/>
<br/> 

**References**  
[https://github.com/biospin/BigBio/blob/master/reference/%EB%A7%88%ED%81%AC%EB%8B%A4%EC%9A%B4.md](https://github.com/biospin/BigBio/blob/master/reference/%EB%A7%88%ED%81%AC%EB%8B%A4%EC%9A%B4.md)