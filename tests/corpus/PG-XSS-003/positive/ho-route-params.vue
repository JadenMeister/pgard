<!-- corpus: expect=PG-XSS-003 -->
<template>
  <h1 v-html="'Hello <i>' + $route.params.name + '</i>'"></h1>
</template>
