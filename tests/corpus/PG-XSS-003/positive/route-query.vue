<!-- corpus: expect=PG-XSS-003 -->
<template>
  <h2 v-html="`Results for ${$route.query.q}`"></h2>
</template>
