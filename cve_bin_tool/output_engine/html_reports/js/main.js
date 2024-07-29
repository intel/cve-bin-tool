function searchProductsScanned() {
    let input = document.getElementById('searchInput')
    let filter = input.value.toLowerCase()
    let ul = document.getElementById('listProducts')
    let li = ul.getElementsByClassName('list-group-item-action')

    for (let i = 0; i < li.length; i++) {
        let txtValue = li[i].textContent || li[i].innerText
        if (txtValue.toLowerCase().indexOf(filter) > -1) {
            li[i].style.display = ''
        } else {
            li[i].style.display = 'none'
        }
    }
}

function analysisShadowToggle(ele) {
    ele.classList.toggle('shadow-lg')
}

function modeInteractive() {
    var div_interactive = document.getElementById('interactive_mode')
    var div_print = document.getElementById('print_mode')
    div_interactive.style.display = 'block'
    div_print.style.display = 'none'
}

function modePrint() {
    var div_interactive = document.getElementById('interactive_mode')
    var div_print = document.getElementById('print_mode')
    div_interactive.style.display = 'none'
    div_print.style.display = 'block'
}

function handleActive(key, id) {
    document
        .getElementById(id)
        .getElementsByClassName('active')[0]
        .classList.remove('active')
    document.getElementById(id).children[key].classList.add('active')
}

function filterCVEs(remark, id) {
    const classes = ['new', 'confirmed', 'mitigated', 'unexplored', 'false_positive', 'not_affected']
    for (let i = 0; i < 6; i++) {
        let ele = document
            .getElementById(`listCVE${id}`)
            .getElementsByClassName(classes[i])[0]
        if (remark == 'all' || classes[i] === remark) ele.style.display = ''
        else ele.style.display = 'none'
    }
}

function filterByRemark(key, id) {
    const classes = [
        'all',
        'new',
        'confirmed',
        'mitigated',
        'unexplored',
        'false_positive',
        'not_affected',
    ]
    handleActive(key, `list-cve${id}`)
    filterCVEs(classes[key], id)
}

function updateCount(ele, remark) {
    if (remark === 'all') {
        ele.getElementsByClassName('cve-count')[0].innerHTML = ele
            .getElementsByClassName('cve-count')[0]
            .getAttribute('total-cve-count')
        return
    }
    ele.getElementsByClassName('cve-count')[0].innerHTML =
        ele.nextElementSibling.getElementsByClassName(remark)[0].childElementCount
}

function filterProducts(remark) {
    let ul = document.getElementById('listProducts')
    let li = ul.getElementsByClassName('list-group-item-action')

    for (let i = 0; i < li.length; i++) {
        let remarks = li[i].getAttribute('remarks')
        if (remarks === null) continue
        if (remark === 'all' || remarks.indexOf(remark) > -1) {
            li[i].style.display = ''
            updateCount(li[i], remark)
        } else {
            li[i].style.display = 'none'
        }
    }
}

function filterProductsByRemark(key) {
    const classes = [
        'all',
        'new',
        'confirmed',
        'mitigated',
        'unexplored',
        'false_positive',
        'not_affected',
    ]
    handleActive(key, 'filter-products')
    filterProducts(classes[key])
}
